import os
import socket
import json
import re
import logging
import smtplib
import requests
import jinja2
from datetime import datetime
import pytz
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from utils.time import parse_rfc3339_ns

logger = logging.getLogger("unicorcli")

# Add a hash of new alerts in a file if they are new
def register_new_alert(alerts_database, alerts_database_max_size, alert):
    try:
      with open(alerts_database, 'r+') as file:
        hashes = file.read().splitlines()
        if alert not in hashes:
            logger.debug("Registering new alert in {} : {}".format(alerts_database, alert))
            try:
                # Trim the database if it is bigger than its max size and add our alert 
                if len(hashes) >= alerts_database_max_size:
                    hashes = hashes[-(alerts_database_max_size - 1):]
                hashes.append(alert)
                file.seek(0)
                file.truncate()
                file.write('\n'.join(hashes) + '\n')
                return True
            except IOError as e:
                logger.warning("Error writing to {}: {}".format(alerts_database.e))
                return False
            return True
      return False
    except IOError as e:
        logger.warning("Error accessing file {}: {}".format(alerts_database.e))
        return False
    return False


def messaging_webhook_alerts(match, config, alert_pattern, alerts_database, alerts_database_max_size, alert_type):
    #logger.debug("messaging_webhook hook {}".format(config['webhook']))

    msg = ""
    # Parsing MISP event(s) associate with the IOC
    misp_events = ""
    misp_tags = ""
    misp_ioc = ""
    misp_ioc_addition = ""
    
    if 'correlation' in match and 'misp' in match['correlation'] and 'events' in match['correlation']['misp']:
        events = match['correlation']['misp']['events']
        if events:
            for event in events:
                misp_events += "[" + event.get('organization') + "] "
                misp_events += "<" + event.get('event_url') + "|" + event.get('info')  + ">\n"

                
                # Extract the 3 first tags of each event associated with the IOC
                tags = event.get('tags', [])
                for tag in tags[:3]:
                    misp_tags += tag['name'].replace('"', '\\"') + ", "  

            # formatting the collected data

            if misp_tags.endswith(", "):
                misp_tags = misp_tags[:-2]        

            misp_ioc += "`" + event.get('ioc').replace('.', '[.]') + "` (" + event.get('ioc_type') + ")\n"
            misp_ioc_addition += "- *MISP IOC date*: " + event.get('publication') + "\n"
            if event.get('comment'):
                misp_ioc_addition += "- *MISP IOC Comment*: " + event.get('comment').replace('\n', ', ') + "\n"
        else:
            misp_events = "[No MISP event found]\n"
    else:
        logger.warning("No correlation data found for {}".format(alert_pattern))


    # Assembling our messaging_webhook message
    msg += misp_events
    if misp_tags:
        msg += "*tags*: \"" + misp_tags + "\"\n"
    
    msg += "- *IOC*: `" + match.get('ioc').replace('.', '[.]') + "`\n"
    msg += misp_ioc_addition
    if match.get('uid'):
        msg += "UID: " + match['uid']
        
    dt = datetime.strptime(match['timestamp'][:26], "%Y-%m-%dT%H:%M:%S.%f")

    if match.get('url'):
        msg += "[*Detection*](" + match['url'] + ")"
    else:
        msg += "*Detection*" 

    msg += " (" + dt.strftime("%Y-%m-%d %H:%M:%SZ") + "):\n"+ match['detection']

    logger.debug("MSG: {}".format(msg))
    if match.get('uid'):
        logger.info("Alerting about: {}: {} ".format(match['uid']), match['detection'])
    else:
        logger.info("Alerting about: {} ".format( match['detection'])) 
    # SENDING!

    payload = {"text": f"🦄 [Unicor]: {msg}"}
    headers = {"Content-type": "application/json"}

    try:
        
        response = requests.post(config['webhook'], headers=headers, json=payload)
        logger.debug("Webhook: {} - {}".format(response.status_code, response.text))
        response.raise_for_status()  # This will raise an HTTPError if the response was an HTTP error


        # If the request worked, then register the alert in our "database" to avoir duplicate alerts
        register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)


    except requests.exceptions.RequestException as e:
        logger.warning("Webhook post failed: {}".format(e))

def email_alerts(alerts, config, summary = False):

    if not alerts:
        logger.debug("No alerts to dispatch")
        return None
    # Define a custom filter to enumerate elements
    def enumerate_filter(iterable):
        return enumerate(iterable, 1)  # Start counting from 1
    # Connecting to the mail server
    smtp = smtplib.SMTP(config['server'], config['port'])

    template_file = Path(config['template'])

    # Set up template
    email_template_loader = jinja2.FileSystemLoader(searchpath = template_file.parent)
    email_template_env = jinja2.Environment(loader = email_template_loader)
    # To allow the use of the timedelta and pytz inside the Jinja2 templates
    email_template_env.globals.update(timedelta = timedelta)
    email_template_env.globals.update(pytz = pytz)
    # Add the custom filter to the Jinja2 environment
    email_template_env.filters['enumerate'] = enumerate_filter

    email_template = email_template_env.get_template(template_file.name)

    outgoing_mailbox = []

    if summary:
        # Load all alerts in one template
        email_body = email_template.render(alerts=alerts)

        msg_root = MIMEMultipart('related')
        msg_root['Subject'] = str(config["subject"])
        msg_root['From'] = config["from"]
        msg_root['To'] = config["summary_to"]
        msg_root['Reply-To'] = config["from"]
        msg_root.preamble = 'This is a multi-part message in MIME format.'
        msg_alternative = MIMEMultipart('alternative')
        msg_root.attach(msg_alternative)
        msg_text = MIMEText(str(email_body), 'html', 'utf-8')
        msg_alternative.attach(msg_text)

        outgoing_mailbox.append(msg_root)

    else:
        # Group emails per destination in email.mappings
        for sensor, sensor_data in alerts.items():
            if sensor in config['mappings']:
                email_body = email_template.render(alerts={sensor:sensor_data})
                msg_root = MIMEMultipart('related')
                msg_root['Subject'] = str(config["subject"])
                msg_root['From'] = config["from"]
                msg_root['To'] = config["mappings"][sensor]['contact']
                msg_root['Reply-To'] = config["from"]
                msg_root.preamble = 'This is a multi-part message in MIME format.'
                msg_alternative = MIMEMultipart('alternative')
                msg_root.attach(msg_alternative)
                msg_text = MIMEText(str(email_body), 'html', 'utf-8')
                msg_alternative.attach(msg_text)

                outgoing_mailbox.append(msg_root)
            else:
                logger.warning("Sensor {} not configured for email alerting".format(sensor))



    for mail in outgoing_mailbox:
        # Send the email
        smtp.sendmail(mail['From'], mail['To'], mail.as_string())
        logging.debug('Sending email notification to {}'.format(mail['To']))

    smtp.quit()
