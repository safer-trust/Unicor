import click
from datetime import datetime
from subcommands.utils import make_sync
from utils import file as unicor_file_utils
from utils import time as unicor_time_utils
from utils import correlation as unicor_correlation_utils
from utils import alert as unicor_alerting_utils
import logging
import hashlib
import jinja2
from datetime import datetime, timedelta
import time
import jsonlines
from pymisp import PyMISP
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)

def sha256_hash(text):
    sha256 = hashlib.sha256()
    sha256.update(text.encode('utf-8'))
    return sha256.hexdigest()


def if_alert_exists(alerts_database, alert):
    with open(alerts_database, 'r') as file:
        hashes = set(file.read().splitlines())
    return alert in hashes

@click.command(help="Send alerts to pre-defined destinations like Slack")
@click.argument(
    'files',
    nargs=-1,
    type=click.Path(
        file_okay=True,
        dir_okay=True,
        readable=True,
        allow_dash=True
    )
)
@click.option(
    'logging_level',
    '--logging',
    type=click.Choice(['INFO','WARN','DEBUG','ERROR']),
    default="INFO"
)

@click.pass_context
def alert(ctx,
    **kwargs):
    alerts_counter = 0
    alerting_config = ctx.obj['CONFIG']['alerting']
    correlation_config = ctx.obj['CONFIG']['correlation']
    alerts_database = correlation_config['alerts_database']
    alerts_database_max_size = correlation_config['alerts_database_max_size']
    max_alerts_counter = alerting_config['max_alerts']
    if not kwargs.get('files'):
        files = [correlation_config['output_dir']]
    else:
        files = kwargs.get('files')
    
    # Make sure the alerts_database actually exists.
    try:
        if ( not Path(alerts_database).exists() ):
            with open(alerts_database, 'w') as file:
                pass
        if ( not Path(alerts_database).is_file() ):
            logger.error("Alerts database file %s exists but is not a file." % ( alerts_database ))
            exit(1)
    except Exception as e:
        print("Error creating alerts database file %s: %s" % ( alerts_database, e))
        exit(1)

    # Loading the list of IOCs currently valid
    malicious_iocs = set()
    for path in (
        correlation_config['malicious_domains_file'],
        correlation_config['malicious_ips_file'],
    ):
        with open(path, "r") as f:
            malicious_iocs.update(
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            )
        
    # Iterating through the file or the directory
    for file in files:
        file_path = Path(file)
        file_paths = [file_path] if file_path.is_file() else file_path.rglob('*')
        for file_path in file_paths:      
            # Processing each file in the directory
            if file_path.is_file():
                alerts, _ =  unicor_file_utils.read_file(file_path)
                # this is an iterator which is not guaranteed to have a length or size.
                #logger.info("{} alerts to be processed in {}".format(len(alerts), file_path))  
                # Processing each alert in each file                    
                try: # Going through each of the alerts
                    
                    all_alert_patterns = set() # To track all alert patterns in this batch
                    for match in alerts:
                                # Alerting strictly on IOCs currently loaded by fetch-iocs as per Unicor config
                                # Only alerts containing these IOCs will be kept     
                                # Note: in DNS mode, 'ioc' may be a domain or one or multiple IP addresses. in DNS mode, match.get('ioc') is not populated yet.
                                if  match.get('ioc') and match.get('ioc') not in malicious_iocs:
                                    logger.debug(
                                        "Alert dismissed: '{}' not found in Unicor ioc files".format(match.get('ioc'))
                                    )
                                    logger.debug("Dissmissed: {}".format(match))
                                    continue
                                
                                # DEDUPLICATION and REPEATING alerts management
                                
                                # Making a string from the timestamp that should cover a 24h window
                                if match.get('detections'): # In case we have multiple detection, we take the first
                                    first_timestamp = min(d["timestamp_rfc3339ns"] for d in match["detections"])
                                    dt = datetime.strptime(first_timestamp[:26], "%Y-%m-%dT%H:%M:%S.%f")
                                else: # We have a single detection
                                    dt = datetime.strptime(match['timestamp'][:26], "%Y-%m-%dT%H:%M:%S.%f")
                                epoch_time = int(time.mktime(dt.timetuple()))
                                truncated_timestamp = epoch_time - (epoch_time % 86400)
                                
                                # Go through each candidate alert, and check if we have seen it in that time window
                                try:
                                    # One alert can have one or multiple detections
                                    
                                    if match.get('detections'): # We have multiple detections
                                    
                                        # Go through each detection, and "pop" out the redundant entries
                                        for i in reversed(range(len(match["detections"]))):
                                            detection_entry = match["detections"][i]
                                            alert_pattern = sha256_hash(detection_entry["detection"] + match.get('ioc') + str(truncated_timestamp))
                                            
                                            if (if_alert_exists(alerts_database, alert_pattern) or alert_pattern in all_alert_patterns):
                                                logger.debug("Duplicate alert: {}".format(detection_entry["detection"] + match.get('ioc') + str(truncated_timestamp)))
                                                # Remove redundant detection in place
                                                match["detections"].pop(i)
                                            else:
                                                logger.debug("New alert: {}".format(detection_entry["detection"] + match.get('ioc') + str(truncated_timestamp)))
                                            all_alert_patterns.add(alert_pattern)
                                            
                                        # Re-flatten the detections in case we went from multiple detections to a single detection due to duplicates
                                        match = unicor_correlation_utils.flatten_detections(match)
                                        # Have all the detections in this alert been seen before?
                                        if not (match.get("detections") or match.get("detection")):
                                            continue
                                        #
                                    else: # We have a single detection
                                        alert_pattern  =  sha256_hash(match['detection'] + match.get('ioc') + str(truncated_timestamp))
                                        if if_alert_exists(alerts_database, alert_pattern):
                                            logger.debug("Redundant alert, skipping: {}".format(alert_pattern))
                                            continue 
                                

                                    logger.debug(f"Alert for: {match}")
                                except  Exception as e:  # Capture specific error details        
                                    logger.error("Failed to parse JSON: {}, skipping. Error: {}".format(match, str(e)))
                                    continue
                                
                                # At this stage, each remaining alert needs to be sent, if it is under the threshold!       
                                if alerts_counter < max_alerts_counter:
                                    logger.debug("Sending an alert for: {}".format(alert_pattern))
                                    if alerts_counter == max_alerts_counter - 1:
                                        if match.get('detections'): # In case we have multiple detections
                                            match["detections"][-1]["detection"] += "\n\n*WARNING*: TOO MANY ALERTS, NOT SENDING MORE, CHECK UNICOR LOGS."
                                        else:  #We have a single detection            
                                            match['detection'] += "\n\n*WARNING*: TOO MANY ALERTS, NOT SENDING MORE, CHECK UNICOR LOGS."
                                    
                                    for alert_type, alert_conf in ctx.obj['CONFIG']['alerting'].items():
                                        logger.debug("Alerting via {}".format(alert_type))
                                        # Preparing and send alerts for specific destinations
                                        if alert_type == "messaging_webhook":
                                            unicor_alerting_utils.messaging_webhook_alerts(match, alerting_config['messaging_webhook'], alert_pattern, alerts_database, alerts_database_max_size, alert_type)
                                        if alert_type == "telegram":
                                            unicor_alerting_utils.messaging_webhook_alerts(match, alerting_config['telegram'], alert_pattern, alerts_database, alerts_database_max_size, alert_type)
                                        if alert_type == "email":           
                                            unicor_alerting_utils.email_alerts(match, alerting_config['email'], summary=False)
                                if alerts_counter == max_alerts_counter:
                                    logger.warning("Too many alerts to be sent, sent only {}".format(max_alerts_counter))
                                alerts_counter += 1

                                # Here we need to catch an exception.
                                # If the request worked, then register the alert in our "database" to avoir duplicate alerts
                                #register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)

                except Exception as e:  # Capture specific error details        
                        logger.error("Failed to parse {}, skipping. Error: {}".format(file, str(e)))
                        continue
                logger.debug("Deleting content of {}".format(file_path))
                with open(file_path, 'w') as file:
                    file.write("")  # Write an empty string to the file and automatically close it

   # if not len(pending_alerts):
    #    logger.info("No alert to be sent.")
