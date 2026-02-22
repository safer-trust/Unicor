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
from datetime import timedelta

logger = logging.getLogger(__name__)

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

def parse_msg(path, variables):
    # Define the custom enumerate filter for Jinja2
    def enumerate_filter(iterable):
        return enumerate(iterable, 1)

    # Path to the template file
    template_file = Path(path)

    # Set up Jinja2 environment and loader
    template_loader = jinja2.FileSystemLoader(searchpath=template_file.parent)
    template_env = jinja2.Environment(loader=template_loader)
    # To allow the use of the timedelta and pytz inside the Jinja2 templates
    template_env.globals.update(timedelta = timedelta)
    template_env.globals.update(pytz = pytz)
    # Add the custom filter to the Jinja2 environment
    template_env.filters['enumerate'] = enumerate_filter

    # Load the template
    template = template_env.get_template(template_file.name)
    try:
        msg = template.render(variables)
    except jinja2.TemplateError as e:
        logger.error(f"Unexpected error while rendering alert template in {path}: {e}")
        msg = template.render(alerts=variables)  # Second attempt

    return msg

def build_msg(path, match):
    # Load all alerts in one template
    timestamp = ""
    if not match.get('detections'): # We have a single detection, we need to extract + format timestamp
        dt = datetime.strptime(
            (match.get("timestamp") or match.get("timestamp_rfc3339ns"))[:26], "%Y-%m-%dT%H:%M:%S.%f")
        timestamp =  dt.strftime("%Y-%m-%d %H:%M:%SZ")
    context = {
        'events': match.get('correlation', {}).get('misp', {}).get('events', []),
        'match': match,
        'timestamp': timestamp,
    }
    msg = parse_msg(path, context)
    return msg

def messaging_webhook_alerts(match, config, alert_pattern, alerts_database, alerts_database_max_size, alert_type):
    #logger.debug("messaging_webhook hook {}".format(config['webhook']))
#    if 'correlation' in match and 'misp' in match['correlation'] and 'events' in match['correlation']['misp']:
    if match.get('correlation', {}).get('misp', {}).get('events'):
        # Let's build a message
        msg = build_msg(config['template'], match)            
    else:
        logger.error("No MISP correlation data found for {}".format(alert_pattern))
        # Alerting anyway, without any MISP context
        msg = build_msg(config['template'], match)            
    logger.debug("MSG: {}".format(msg))
    
    alert_log = match.get("detections", [{}])[0].get("detection", match.get("detection"))  
    logger.info(f"Alerting about: {match['uid'] + ': ' if 'uid' in match else ''}{alert_log}") 
    # SENDING!
    
    if ( config.get('webhook') or config.get('webhook_file') ):
        # Load webhook
        webhook_url = None

        if ( config.get('webhook') and config.get('webhook_file') ):
            logger.error("Both webhook and webhook_file config params set, please set only one.")
            exit(1)

        # load the webhook url from a secrets file if provided
        if config.get('webhook_file'):
            try:
                with open(config.get('webhook_file'), 'r') as f:
                    webhook_url = f.readline()
                    webhook_url = webhook_url.strip()
                if ( webhook_url is None or webhook_url == '' ):
                    logger.error("The webhook_file %s is empty or could not be read" % ( config.get('webhook_file') ))
                    exit(1)
            except FileNotFoundError as e:
                logger.error("Failure opening webhook_file %s: %s" % ( config.get('webhook_file'), e))
                exit(1)
        if config.get('webhook'):
            webhook_url = config.get('webhook')
            if ( webhook_url is None or webhook_url == '' ):
                logger.error("The webhook config option is empty")
                exit(1)
        if webhook_url is None:
            logger.error("Unable to load a webhook url.")
            exit(1)

        payload = {"text": f"{msg}"}
        headers = {"Content-type": "application/json"}
        try:
            response = requests.post(webhook_url, headers=headers, json=payload)
            logger.debug("Webhook: {} - {}".format(response.status_code, response.text))
            response.raise_for_status()  # This will raise an HTTPError if the response was an HTTP error
            # If the request worked, then register the alert in our "database" to avoir duplicate alerts
            register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)
        except requests.exceptions.RequestException as e:
            logger.warning("Webhook post failed: {}".format(e))
            
    if config.get('telegram_chat_id'):
        # Load the telegram_bot_token from a secrets file
        telegram_bot_token = None
        if ( config.get('telegram_bot_token') and config.get('telegram_bot_token_file') ):
            logger.error("Both telegram_bot_token and telegram_bot_token_file set, please choose only one.")
            exit(1)
        if ( config.get('telegram_bot_token') is None and config.get('telegram_bot_token_file') is None ):
            logger.error("telegram_chat_id config option is set, but both telegram_bot_token and telegram_bot_token_file are missing")
            exit(1)
        if config.get('telegram_bot_token_file'):
            try:
                with open(config.get('telegram_bot_token_file'), 'r') as f:
                    telegram_bot_token = f.readline()
                    telegram_bot_token = telegram_bot_token.strip()
                if ( telegram_bot_token is None or telegram_bot_token == '' ):
                    logger.error("The telegram_bot_token_file %s is empty or could not be read" % ( config.get('telegram_bot_token_file') ))
                    exit(1)
            except FileNotFoundError as e:
                logger.error("Failure opening telegram_bot_token_file %s: %s" % ( config.get('telegram_bot_token_file'), e))
                exit(1)
        if config.get('telegram_bot_token'):
            telegram_bot_token = config.get('telegram_bot_token')
            if ( telegram_bot_token is None or telegram_bot_token == '' ):
                logger.error("The webhook config option is empty")
                exit(1)

        payload = {'chat_id': config['telegram_chat_id'], 'text': msg}
        telegram_url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage"

        try:
            response = requests.post(telegram_url, data=payload)
            logger.debug("Telegram: {} - {}".format(response.status_code, response.text))
            response.raise_for_status()  # This will raise an HTTPError if the response was an HTTP error
            register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)
        except requests.exceptions.RequestException as e:
            logger.warning("Telegram post failed: {}".format(e))

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
