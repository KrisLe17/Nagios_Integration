
import time
time0 = time.time()
import urllib3 # ignore silly warnings about insecure requests to Nagios API
from agios import Agios
from servicenow import ServiceNow
from configuration import Configuration


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# This gives us a way to get information from the config file (config.yaml)
config = Configuration(r"config.yaml")

# This gives us our board details (hostnames, api keys, whether we should verify the ssl cert) for each board
board_configs = config.get_board_configs()

# This is where we'll store our boards (agios instances)
boards = []

# Take information we got from the config file (config.yaml) and create board instances, adding each to the "boards" array
for board_config in board_configs:
    boards.append(Agios(board_config["api_key"], board_config["hostname"], board_config["timezone"],
                        should_verify_https_cert=board_config["should_verify_https_cert"], ))

# Grab the SNOW credentials to make tickets
snow_credentials = config.get_credentials()
# Create an instance of our SNOW API, so we can submit tickets
service_now = ServiceNow(snow_credentials["url"], snow_credentials["username"], snow_credentials["pass"])

time1 = time.time()

def scan_and_respond():
    # This is where we'll store service alerts we need to handle
    service_alerts = []
    all_alerts = []

    print("Gathering Alerts...")
    for board in boards:
        # Add each service alert to the "service_alerts" array
        service_alerts.append(board.group_alerts_by_host())
        #all_alerts.append(board.group_alerts_by_host(True))
        all_alerts.append(board.group_alerts_by_host(True))
        # acked alerts

    # Go through our array of alerts we need to handle, and create tickets for each one
    for board in service_alerts:
        # print("board is:", board)
        for current_host in board:
            descriptions = format_alert(board, current_host)
            found_tickets = service_now.api_get_open_ticket(descriptions[0])['result']
            found_downs = service_now.api_get_open_ticket(current_host + " is DOWN")['result']
            # if len(found_downs) != 0:
            #     print("found a down host ticket for ", current_host)
            # print("found tickets:", found_tickets)
            if len(found_tickets) == 0 and len(found_downs) == 0:
                print("Creating Ticket for ", descriptions[0], " \n ", descriptions[1])
                service_now.create_incident(descriptions[0], descriptions[1], board[current_host]["impact"])
            else:
                #print(found_tickets)
                print("ticket dropped for ", descriptions[0])

   

    # This section submits SNOW incidents for persistent alerts that have been acked over 7 days
    for board in all_alerts:
        for current_host in board:
            # print("second board is:", board)
            if board[current_host]["duration"] > 10080: #If the alert is over 7 days old and not on scheduled downtime
                descriptions = format_alert(board, current_host)
                if "SSL Certificate" in descriptions[0]:
                    print("Persistent SSL Cert Error", descriptions[0], "Skipped")
                else:
                    descriptions[0] = "Persistent Alert - " + descriptions[0]
                    descriptions[1] = "This alert is over 7 days old, please check and escalate the alert.\n" + descriptions[1]
                    found_tickets = service_now.api_get_open_ticket(descriptions[0])['result']
                    found_downs = service_now.api_get_open_ticket("Persistent Alert - " + current_host + " is DOWN")['result']
                    if len(found_tickets) == 0 and len(found_downs) == 0:
                        # print("found host over duration specified: ", descriptions[0])
                        service_now.create_incident(descriptions[0], descriptions[1], board[current_host]["impact"])
                    else:
                        print("ticket dropped for ", descriptions[0])

    # This section closes SNOW incidents where the alerts have cleared
    compare_strings=[]
    skip_boards=[]
    open_incidents = service_now.api_get_open_ticket(created_by=service_now.nagios_integration_id, assignment_group=service_now.crc_id)
    #print("open incidents", open_incidents)
    for board in all_alerts:
        for current_host in board:
            compare_strings.append(format_alert(board, current_host)[0])

    for board in service_alerts: ## add any currently open alerts to the compare strings in the event that a host alert overrode a service alert in all alerts
        for current_host in board:
            compare_strings.append(format_alert(board, current_host)[0])

    for board in boards:  ## don't close alerts that are on boards we can't currently connect to...
        if not board.connected:
            skip_boards.append(board.api_host)

    #print("skip boards", skip_boards)

    #print("compare strings", compare_strings)
    alerts_for_closer = [incident for incident in open_incidents["result"] if incident["short_description"] not in compare_strings and "Persistent Alert" not in incident["short_description"]]
    #print(len(alerts_for_closer))
    for skip in skip_boards: ### remove alerts that are on boards we can't connect to
        alerts_for_closer = [incident for incident in alerts_for_closer if skip not in incident["description"]]
    #print(len(alerts_for_closer))
    service_now.resolve_incidents(alerts_for_closer)
                


def format_alert(board, current_host):
    short_description = ""
    description = ("NAGIOS XI:" + board[current_host]["board"] + "\n" +
                  "HOST: " + current_host + " \n" +
                  "IP/FQDN: " + board[current_host]["ip"] + " \n" +
                  "DESCRIPTION: " + ' '.join('{} - {}'.format(*service) for service in zip(board[current_host]["service"], board[current_host]["service_status"])))
    if board[current_host]["state"] == "DOWN":
        short_description = current_host + " is DOWN"
    else:
        short_description = current_host + " | " + (board[current_host]["service"][0] + " is "," Multiple Services are ")[len(board[current_host]["service"]) > 1] + board[current_host]["state"]
    return [short_description, description]
    

scan_and_respond()
