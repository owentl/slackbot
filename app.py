from slack_bolt import App, Ack
import os
import re
import logging
import requests
import json

from misp import misp_search
from virustotal import virustotal_search
from servicedesk import ticketRouter, create_ticket
from quarantine import quarantine_approval

logging.basicConfig(level=logging.DEBUG)

# Use the package we installed

#app = App()
# Initializes your app with your bot token and signing secret
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET")
)


@app.message("hello")
def say_hello(message, say):
    user = message['user']
    say(f"Hi there, <@{user}>!")


@app.message("misp")
def misp(message, say):
    search_text = re.sub("misp ", '', message['text'])
    if ',' in search_text:
        st = search_text.split(',')
    if '|' in search_text:
        st = search_text.split('|')
        search_text = re.sub('>', '', st[1])
    # data_out = misp_search(search_text)
    say(misp_search(search_text))

@app.command("/misp")
def misp(ack, say, command):
    ack()
    search_text = command['text']
    if ',' in search_text:
        st = search_text.split(',')
    if '|' in search_text:
        st = search_text.split('|')
        search_text = re.sub('>', '', st[1])
    # data_out = misp_search(search_text)
    say(misp_search(search_text))


@app.message(re.compile("(vt|VT|virustotal|VirusTotal)"))
def virustotal(say, context, message):
    greeting = context['matches'][0]
    search_text = re.sub(greeting, '', message['text'])
    if re.search("^help|Help",search_text):
        say("To query VirusTotal please specify a domain, URL, MD5 or SHA1 hash")
    else:
        data_out = virustotal_search(search_text)
        say(data_out)

@app.command("/virustotal")
def virustotal(ack, say, command):
    ack()
    print(command['text'])
    if re.search("^help|Help",command['text']):
        say("To query VirusTotal please specify a domain, URL, MD5 or SHA1 hash")
    else:
        data_out = virustotal_search(command['text'])
        say(data_out)

@app.message("tickets")
def tickets(say, message, concat):
    search_text = re.sub("tickets", '', message['text']).strip()
    if not search_text:
        search_text = "all"
    say(ticketRouter(search_text))

@app.command("/tickets")
def tickets(ack, say, command):
    ack()
    search_text = command['text'].strip()
    if not search_text:
        search_text = "all"
    say(ticketRouter(search_text))

@app.event("app_home_opened")
def update_home_tab(client, event, logger):
    try:
        # views.publish is the method that your app uses to push a view to the Home tab
        client.views_publish(
            user_id=event["user"],
            view={
                "type": "home",
                "callback_id": "home_view",

                # body of the view
                "blocks": [
                    {
            			"type": "section",
            			"text": {
            				"type": "mrkdwn",
            				"text": "Meet Anton!  Anton is designed to help enhance your experience by allowing you to access your GoSecure data and interact with us in a more productive and simplier way"
            			}
            		},
            		{
            			"type": "section",
            			"text": {
            				"type": "mrkdwn",
            				"text": "• Get a listing of your tickets \n • Get a list of your endpoints \n • Get a list of escalations for endpoints\n • Get a current stats about the MDR service \n • Query GoSecure Threat Intelligence (MISP and VirusTotal) \n • Quarantine an endpoint\n  "
            			}
            		},
            		{
            			"type": "section",
            			"text": {
            				"type": "mrkdwn",
            				"text": "Great to see you here! If you have any questions please ask for help!"
            			}
            		},
                ]
            }
        )

    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")

@app.action('ticket_action')
def quarantine_deny(ack, say, body, respond, client, logger):
    ack();
    ticketRouter(body['actions'][0]['value'])
    say("Endpoint was *not* quarantined!  Thanks for playing!")

@app.middleware  # or app.use(log_request)
def log_request(logger, body, next):
    logger.debug(body)
    return next()

@app.event("app_mention")
def event_test(body, say, logger):
    logger.info(body)
    say("What's up?")

@app.event("reaction_added")
def say_something_to_reaction(say):
    say("OK!")

@app.message("test")
def test_message(logger, body):
    logger.info(body)

@app.message(re.compile("bug"))
def mention_bug(logger, body):
    logger.info(body)


# Start your app
if __name__ == "__main__":
    #app.start(port=int(os.environ.get("PORT", 3000)))
    app.start(3000)
