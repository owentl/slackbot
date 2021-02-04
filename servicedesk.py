import json
import requests
from datetime import datetime
import re

url_base = 'http://xxx.xx.xxx.x:8080/'
api_base = url_base + 'sdpapi/'
sdp_key = ''
headers = {
    "Content-Type":"application/x-www-form-urlencoded"
}
params = {
    "TECHNICIAN_KEY": sdp_key,
    "format":"json"
}

divider = {
    "type": "divider"
}

def ticketRouter(search_text):
    if isinstance(search_text,int):
        get_ticket_status(search_text)
    elif re.search("^help",search_text):
        ticout = "Options include:\nall - List the last 10 tickets for all Customers\ncustomers - List Customers currently tracked\n<customer name> - List tickets for that customer"
    elif re.search("^all",search_text):
        ticout = get_all_tickets(search_text)
    elif re.search("^customer|customers",search_text):
        ticout = get_tickets_customers()
    elif re.search("^notes|Notes",search_text):
        ticout = get_ticket_notes(search_text)
    else:
        ticout = get_all_tickets(search_text)
    return ticout

def create_ticket(endpointid):
    ticketjson = {
        "operation": {
            "details": {
                "requester": "Guest",
                "subject": "Quarantine Endpoint {}".format(endpointid),
                "description": "Quarantine Endpoint",
                "requesttemplate": "Quarantine",
                "priority": "High",
                "site": "Common Site",
                "group": "Network",
                "technician": "administrator",
                "level": "Tier 3",
                "status": "open",
                "service": "Email",
                "account": "MDR Customer"
            }
        }
    }

    data = {
        'data': json.dumps(ticketjson)
    }

    url = api_base + "request/"

    ticket_num = 0;
    result = requests.post(url,data=data,params=params,headers=headers)
    jdata = result.json()
    if jdata['operation']['result']['status'] == "Success":
        ticket_num = jdata['operation']['details']['workorderid']
    return ticket_num

def get_all_tickets(account):
    ticketjson = {
        "operation": {
            "details": {
                "from": "0",
                "limit": "10",
                "filterby": "All_Requests"
            }
        }
    }
    print("Account: {}".format(account))
    if not account == "all":
        ticketjson['operation']['details'].update({"account":account})

    print(ticketjson)
    data = {
        'data': ticketjson
    }
    params2 = {
        "TECHNICIAN_KEY": sdp_key,
        "format":"json",
        'data': json.dumps(ticketjson)
    }
    url = api_base + "request/"
    result = requests.get(url,data=data,params=params2,headers=headers)
    jdata = result.json()
    blocks = {
        "blocks" : [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Ticket Listing"
                }
            }
        ]
    }
    ticout = ""
    if jdata['operation']['result']['status'] == "Success":
        for ticket in jdata['operation']['details']:

            time = int(ticket['createdtime']) // 1000
            tickURL = url_base + "WorkOrder.do?woMode=viewWO&woID={}".format(ticket['workorderid'])
            section = {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "<{}|{}> - _{}_".format(tickURL,ticket['workorderid'],ticket['subject'])
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Customer:* {}".format(ticket['accountname'])
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Requester:* {}".format(ticket['requester'])
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Owner:* {}".format(ticket['technician'])
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Priority:* {}".format(ticket['priority'])
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Status:* {}".format(ticket['status'])
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Overdue/SLA Status:* {}".format(ticket['isoverdue'])
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Created:* {}".format(datetime.fromtimestamp(time))
                    }

                ]
            }
            blocks['blocks'].append(section)
    return blocks

def get_tickets_customers():
    ticketjson = {
        "operation": {
            "details": {
                "from": "0",
                "limit": "25",
                "q": "*"
            }
        }
    }
    data = {
        'data': ticketjson
    }
    params2 = {
        "TECHNICIAN_KEY": sdp_key,
        "format":"json",
        'data': json.dumps(ticketjson)
    }
    url = api_base + "admin/account"
    result = requests.get(url,data=data,params=params2,headers=headers)
    jdata = result.json()

    ticout = ""
    if jdata['operation']['result']['status'] == "Success":
        for ticket in jdata['operation']['details']:
            ticout += "{}\t-\t".format(ticket['AccountName'])
            ticout += "{}\t".format(ticket['Description'])
            ticout += "\n"
    print(ticout)
    return(ticout)
def get_ticket_status(search_text):
    params2 = {
        "TECHNICIAN_KEY": sdp_key,
        "format":"json",
    }
    url = api_base + "request/{}".format(search_text)
    result = requests.get(url,params=params2,headers=headers)
    jdata = result.json()
    print(jdata)

def get_ticket_notes(search_text):
    params2 = {
        "TECHNICIAN_KEY": sdp_key,
        "format":"json",
    }
    url = api_base + "request/{}/notes".format(search_text)
    result = requests.get(url,params=params2,headers=headers)
    jdata = result.json()
    print(jdata)

# Testing.. you can use these to test each function instead of running through slack
# create_ticket(56655)
# get_all_tickets("Elsinore Beer")
# get_tickets_customers()
# get_ticket_status(9)
