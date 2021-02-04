import requests
import json

def misp_search(search_text):
    misp_key = '' #MISP API Key
    url = "https://xx.xx.xx/attributes/restSearch"  #MISP Server
    headers = {
      "Authorization": misp_key,
      "Accept": "application/json",
      'Content-Type': 'application/json'
    }
    payload = {'value':search_text}
    response = requests.post(url,headers=headers,data=json.dumps(payload), verify=False)
    print(response.status_code)
    print(response.text)
    json_data = response.json() if response and response.status_code == 200 else None
    data_out = ""
    blocks = {
        "blocks" : [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Results for *{}*".format(search_text)
                }
            }
        ]
    }
    if json_data['response']['Attribute']:
      for entry in json_data['response']['Attribute']:
        tickURL = "https://xx.x.x.x/events/view/" + entry['event_id']
        if entry['comment'] == "":
            entry['comment'] = 'N/A'
        section = {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "*Category:* {}".format(entry['category'])
                },
                {
                    "type": "mrkdwn",
                    "text": "*Type:* {}".format(entry['type'])
                },
                {
                    "type": "mrkdwn",
                    "text": "*timestamp:* {}".format(entry['timestamp'])
                },
                {
                    "type": "mrkdwn",
                    "text": "*Comment:* {}".format(entry['comment'])
                },
                {
                    "type": "mrkdwn",
                    "text": "<{}|More Info>".format(tickURL,entry['event_id'])
                }
            ]
        }
        blocks['blocks'].append(section)
        blocks['blocks'].append({"type": "divider"})
      #print(data_out)
    else:
      data_out = "No results found"
      section = {
          "type": "context",
          "elements": [
              {
                  "type": "mrkdwn",
                  "text": "No Results Found"
              }
          ]
      }
      blocks['blocks'].append(section)
      blocks['blocks'].append({"type": "divider"})

    # return data_out
    return blocks
    
# use below for local testing
# misp_search("19.123.123.4")
