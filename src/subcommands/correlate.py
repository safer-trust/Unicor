import click
import traceback
from datetime import timedelta
from datetime import datetime
import netaddr
from subcommands.utils import make_sync
from utils import file as unicor_file_utils
from utils import time as unicor_time_utils
from utils import correlation as unicor_correlation_utils
from utils import enrichment as unicor_enrichment_utils
from collections import defaultdict
import logging
import jsonlines
from pymisp import PyMISP
from pathlib import Path
import shutil
import random
import string

logger = logging.getLogger(__name__)

# Return a non-cryptographically-safe random string for
# filename collision avoidance
def file_nocollide_prefix():
    outstr = str(datetime.now().strftime("%s"))
    return outstr + "_" + ''.join(random.choice(string.ascii_letters) for i in range(8))

@click.command(help="Correlate input files and produce matches for potential alerts. Add --retro_disco_lookup to reprocesses input in the list of newer MISP events")
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
    default="DEBUG"
)
@click.option(
    'no_archive',
    '--no_archive',
    is_flag=True,
    help="Delete input after processing instead of archiving it",
    default=False
)
@click.option(
    'retro_disco_lookup',
    '--retro_disco_lookup',
    is_flag=True,
    help="Correlate retrospectively with up to date IOCs",
    default=False
)
@click.option(
    'correlation_output_file',
    '--output-dir',
    type=click.Path(
        file_okay=False,
        dir_okay=True,
        writable=True,
        allow_dash=True
    )
)
@click.option(
    'malicious_domains_file',
    '--malicious-domains-file',
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
)
@click.option(
    'malicious_ips_file',
    '--malicious-ips-file',
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
)
@click.pass_context
def correlate(ctx,
    **kwargs):

    correlation_config = ctx.obj['CONFIG']['correlation']
    max_alerts_counter = ctx.obj['CONFIG']['alerting']['max_alerts']

    # The retro_disco_lookup applies new match criteria to previous events.
    # To do that, we need to save previous events in an archive, which we'll do unless
    # told not to.
    archive_event_files = True
    if kwargs.get('no_archive'):
        logging.info('Will delete input instead of archiving')
        archive_event_files = False

    # Match archived events against more current criteria
    retro_disco_lookup = False
    if kwargs.get('retro_disco_lookup'):
        logging.info("Retro disco mode.")
        retro_disco_lookup = True

    # Make sure the archive_dir is set up and usable.
    # We don't care if it's missing unless we actually need it.
    archive_dir = None
    if ( archive_event_files or retro_disco_lookup ):
        try:
            archive_dir = ctx.obj['CONFIG']['correlation']['archive_dir']
        except KeyError:
            logging.error("Missing from config file: correlation -> archive_dir")
            exit(1)
        if ( not Path(archive_dir).is_dir() ):
            logging.error("archive_dir %s is not a directory or does not exist (symlinks allowed)" % ( archive_dir ))
            exit(1)

    # Make sure the fail_dir is set up and usable.
    fail_dir = None
    try:
        fail_dir = ctx.obj['CONFIG']['correlation']['fail_dir']
    except KeyError:
        logging.error("Missing from config file: correlation -> fail_dir")
        exit(1)
    if ( not Path(fail_dir).is_dir() ):
        logging.error("fail_dir %s is not a directory or does not exist (symlinks allowed)" % ( fail_dir ))
        exit(1)

    # Set up MISP connections
    misp_connections = []
    for misp_conf in ctx.obj['CONFIG']["misp_servers"]:
        misp = PyMISP(misp_conf['domain'], misp_conf['api_key'], ssl=misp_conf['verify_ssl'], debug=misp_conf['debug'])
        if misp:
            misp_connections.append((misp, misp_conf['args']))

    # Set up domain and IP lists to alert on, in domain_attributes and ip_attributes
    domain_attributes = {}
    domain_attributes_metadata = {}
    if 'malicious_domains_file' in correlation_config and correlation_config['malicious_domains_file'] and not retro_disco_lookup:
        domains_iter, _ = unicor_file_utils.read_file(Path(correlation_config['malicious_domains_file']))
        for domain in domains_iter:
            domain_attributes.update({ domain.strip(): 1 })
    else:
        for misp, args in misp_connections:
            attributes = misp.search(controller='attributes', type_attribute='domain', to_ids=1, pythonify=True, **args)
            for attribute in attributes:
                domain_attributes.update({ attribute.value: 1})
                if retro_disco_lookup:
                    if attribute.value in domain_attributes_metadata:
                        if attribute.timestamp > domain_attributes_metadata[attribute.value]:
                            domain_attributes_metadata[attribute.value] = attribute.timestamp
                    else:
                        domain_attributes_metadata[attribute.value] = attribute.timestamp

    ip_attributes = netaddr.IPSet()
    ip_attributes_metadata = {}
    if 'malicious_ips_file' in correlation_config and correlation_config['malicious_ips_file'] and not retro_disco_lookup:
        ips_iter, _ = unicor_file_utils.read_file(Path(correlation_config['malicious_ips_file']))
        for attribute in ips_iter:
            try:
                ip_attributes.add(attribute.strip())
            except ValueError:
                logging.warning("Invalid malicious IP value {}".format(attribute))
    else:
        for misp, args in misp_connections:
            ips_iter = misp.search(controller='attributes', type_attribute=['ip-src','ip-dst'], to_ids=1, pythonify=True, **args)

            for attribute in ips_iter:
                try:
                    ip_attributes.add(attribute.value)
                    if retro_disco_lookup:
                        if attribute.value in ip_attributes_metadata:
                            if attribute.timestamp > ip_attributes_metadata[attribute.value]:
                                ip_attributes_metadata[attribute.value] = attribute.timestamp
                        else:
                            ip_attributes_metadata[attribute.value] = attribute.timestamp
                except ValueError:
                    logging.warning("Invalid malicious IP value {}".format(attribute.value))

    logger.debug("Correlating with {} domains and {} ips".format(len(domain_attributes), len(ip_attributes.iter_cidrs())))
    
    
    # Now that we have MISP data, let's correlate it with input files...
    total_matches = []
    total_matches_minified = []
    if not kwargs.get('files'):
        files = [correlation_config['input_dir']]
    else:
        files = kwargs.get('files')

    # But wait, if we're doing retro lookups, prepend the archive dir so we process it first, 
    # before new events are archived and processed twice.
    if retro_disco_lookup:
        files.insert(0, archive_dir)

    # Iterating through the file or the directory
    for file in files:
        # To avoid duplicating code, we'll prepend the archive dir if needed.
        # The files in the archive dir must not be archived.
        processing_archive_dir = ( file == archive_dir )

        file_path = Path(file)
        file_paths = [file_path] if file_path.is_file() else file_path.rglob('*')
        for path in file_paths:
            if path.is_file():
                # Reading an actual files with one JSON object per line
                file_iter, is_minified = unicor_file_utils.read_file(path)
                if file_iter:
                    try:
                        matches = unicor_correlation_utils.correlate_file(
                            file_iter,
                            domain_attributes,
                            ip_attributes,
                            domain_attributes_metadata,
                            ip_attributes_metadata,
                            is_minified
                        )

                        if len(matches):
                            logger.info("Found {} matches in {}".format(len(matches), path.absolute()))
                            #logger.info("Matches: {}".format(matches['dns']['qname']))
                        else:
                            logger.info("No match found in {}".format(path.absolute()))
                        if is_minified:
                            total_matches_minified.extend(matches)
                        else:
                            total_matches.extend(matches)
                    except:
                        # Add a random string in the dst in case the pipeline keeps dumping the same file name into input.
                        faildst = fail_dir + '/' + file_nocollide_prefix() + '_' + path.name
                        logger.error("Failed to parse {}, skipping and moving to {}".format(path, fail_dir))
                        path.rename(Path(faildst))
                        continue
                else:
                    logger.debug("No data in {}".format(file_path))

                # Do nothing for archived files
                if processing_archive_dir:
                    continue

                # Do something with the file so it's not sitting in the input dir forever
                if archive_event_files:
                    # Add a random string in the dst in case the pipeline keeps dumping t he same file name into input.
                    archivedst = archive_dir + '/' + file_nocollide_prefix() + '_' + path.name
                    logger.info("Archiving {} to {}".format(path, archive_dir))
                    path.rename(Path(archivedst))
                else:
                    logger.info("Archiving disabled, deleting {}".format(path))
                    path.unlink()

  
  
    # Condense matches (detections) that have the same IOC:
    
    condensed_matches = defaultdict(lambda: {"ioc": "", "ioc_type": "", "detections": []})
    for detections in total_matches:
        logger.debug("Detections: {}".format(detections))
        ioc = detections["ioc"]
        
        # Initialize main keys
        condensed_matches[ioc]["ioc"] = ioc
        condensed_matches[ioc]["ioc_type"] = detections["ioc_type"]
        
        # Append nested entries (within the maximum allowed number of detections)
        if len(condensed_matches[ioc]["detections"]) < max_alerts_counter:

    
            condensed_matches[ioc]["detections"].append({
             "timestamp_rfc3339ns": detections.get("timestamp_rfc3339ns", "").rstrip("Z"),
             "detection": detections["detection"],
             "uid": detections.get("uid", ""),
             "url": detections.get("url", ""),
         })

    # Now flatten if there's only one detection
#     flattened_matches = []
#    for ioc, data in condensed_matches.items():
#        detections = data["detections"]
#        if len(detections) == 1:
#            # Merge ioc and ioc_type into the detection dict
#            single_detection = {
#            **detections[0],
#            "ioc": data["ioc"],
#            "ioc_type": data["ioc_type"]
#            }
#            flattened_matches.append(single_detection)
#        else:
#            flattened_matches.append(data) 
#
#    total_matches = flattened_matches
    
    total_matches = unicor_correlation_utils.flatten_detections(condensed_matches)
        
    #logger.debug("Enrich input: {}".format(total_matches))
    if not len(total_matches):
        logger.info("No MISP correlation found in the input.")

    # We have a list of matches, let's enrich them with MISP meta data
    else:
        # This part is now indented to NOT alert if there is no corresponding IOC in MISP
        enriched = unicor_enrichment_utils.enrich_logs(total_matches, misp_connections, False)
        enriched_minified = unicor_enrichment_utils.enrich_logs(total_matches_minified, misp_connections, True)


        logger.debug("Final output: {}{}".format(enriched,enriched_minified))
        # Output to directory
        # Write full enriched matches to matches.json

        to_output = enriched + enriched_minified
        with jsonlines.open(Path(correlation_config['output_dir'], "matches.json"), mode='a') as writer:
            for document in to_output:
                writer.write(document)

