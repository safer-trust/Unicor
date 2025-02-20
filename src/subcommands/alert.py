import click
from datetime import datetime
import ipaddress
from subcommands.utils import make_sync
from utils import file as unicor_file_utils
from utils import time as unicor_time_utils
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

    # iterate through alert configs enabled
    for alert_type, alert_conf in ctx.obj['CONFIG']['alerting'].items():
        logger.debug("Alerting via {}".format(alert_type))
        # Set up mailing here


    if not kwargs.get('files'):
        files = [correlation_config['output_dir']]
    else:
        files = kwargs.get('files')

    for file in files:
        file_path = Path(file)
        # Reading an alert file
        if file_path.is_file():
            alerts, _ =  unicor_file_utils.read_file(file_path, delete_after_read=False)
            logger.info("{} pending alerts".format(len(alerts)))  
            if alerts:
                try:
                    # Going through each of the alerts
                       for match in alerts:

                            # Making a string from the timestamp that should cover a 24h window
                            dt = datetime.strptime(match['timestamp'][:26], "%Y-%m-%dT%H:%M:%S.%f")
                            epoch_time = int(time.mktime(dt.timetuple()))
                            truncated_timestamp = epoch_time - (epoch_time % 86400)
                            
                            
                            
                            #logger.debug("Truncated timestamp: {} - {}".format(truncated_timestamp, match['ioc']))
                            
                            # First, make sure we are not about to create a duplicate alert
                            # match['timestamp'][:-1][:16]
                            alert_pattern  =  sha256_hash(match['detection'] + match['ioc'] + str(truncated_timestamp))

                            if if_alert_exists(alerts_database, alert_pattern):
                                logger.debug("Redundant alert, skipping: {}".format(alert_pattern))
                                continue 
                            
                            # At this stage, each remaining alert needs to be sent, if it is under the threshold!
                            
                            alerts_counter += 1
                            
                            if alerts_counter < max_alerts_counter:
                                logger.debug("Sending an alert for: {}".format(alert_pattern))
                                
                                if alert_type == "messaging_webhook":
                                    unicor_alerting_utils.messaging_webhook_alerts(match, alerting_config['messaging_webhook'], alert_pattern, alerts_database, alerts_database_max_size, alert_type)
                                if alert_type == "email":           
                                    unicor_alerting_utils.email_alerts(match, alerting_config['email'], summary=False)
                            
                            else:
                                logger.warning("Too many alerts to be sent, sending only {}".format(max_alerts_counter))
                            
                            # Here we need to catch an exception.
                            # If the request worked, then register the alert in our "database" to avoir duplicate alerts
                            #register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)

                except Exception as e:  # Capture specific error details        
                    logger.error("Failed to parse {}, skipping. Error: {}".format(file, str(e)))
                    continue
            logger.debug("Deleting content of: {}".format(file_path))
            with open(file_path, 'w') as file:
                file.write("")  # Write an empty string to the file and automatically close it

        else:
            for nested_path in file_path.rglob('*'):
                if nested_path.is_file():
                    alerts, _ =  unicor_file_utils.read_file(nested_path, delete_after_read=False)
                    logger.info("{} pending alerts".format(len(alerts)))  
                    if alerts:
                        try:
                                # Going through each of the alerts
                                for match in alerts:

                                        # First, make sure we are not about to create a duplicate alert
                                        alert_pattern  = sha256_hash(match['detection'] + match['ioc'] + match['timestamp'][:-1][:16])

                                        if if_alert_exists(alerts_database, alert_pattern):
                                            logger.debug("Redundant alert, skipping: {}".format(alert_pattern))
                                            continue 
                                        
                                        # At this stage, each remaining alert needs to be sent, if it is under the threshold!
                                        
                                        alerts_counter += 1
                                        
                                        if alerts_counter < max_alerts_counter:
                                            logger.debug("Sending an alert for: {}".format(alert_pattern))
                                                    
                                            if alert_type == "messaging_webhook":
                                                unicor_alerting_utils.messaging_webhook_alerts(match, alerting_config['messaging_webhook'], alert_pattern, alerts_database, alerts_database_max_size, alert_type)
                                            if alert_type == "email":           
                                                unicor_alerting_utils.email_alerts(match, alerting_config['email'], summary=False)
                                        else:
                                            logger.warning("Too many alerts to be sent, sending only {}".format(max_alerts_counter))

                        except Exception as e:  # Capture specific error details        
                                logger.error("Failed to parse {}, skipping. Error: {}".format(file, str(e)))
                                continue

            logger.debug("Deleting content of {}".format(file_path))
            with open(nested_path, 'w') as file:
                file.write("")  # Write an empty string to the file and automatically close it

   # if not len(pending_alerts):
    #    logger.info("No alert to be sent.")


