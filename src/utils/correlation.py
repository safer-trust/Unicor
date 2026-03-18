import json
import logging
from . import time as unicor_time_utils
from cachetools import cached
from cachetools.keys import hashkey
import pytz
import netaddr

logger = logging.getLogger("unicorcli")

@cached(cache={}, key=lambda domain, domain_set: hashkey(domain))
def correlate_domain(domain, domain_set):
    if domain_set.get(domain) is not None:
        return True
    else:
        return False

@cached(cache={}, key=lambda ip_structure, ip_set: hashkey(ip_structure['rdata']))
def correlate_ip(ip_structure, ip_set):
    if ip_structure['rdatatype'] == 'A' or ip_structure['rdatatype'] == 'AAAA':
        if ip_structure['rdata'] in ip_set:
            return True
    return False


def correlate_events(lines, shared_data):
    (domain_attributes, ip_attributes, domain_attributes_metadata, ip_attributes_metadata, is_minified) = shared_data
    total_matches = []
    ips = []
    domain = ""
    for match in lines:
    # Extract the timestamp, domain and ips
        #logger.debug("Parsing: {}".format(match))

        # Testing if input is pdns. If so, input can be a domain, an array of IPs, or both
        if match.get('dns', {}).get('id') is not None:
            #logger.debug("DNS mode")
            match['ioc_type'] = "dns" #Not sure yet if ioc_type is an IP or a domain
            if is_minified:
                try:
                    timestamp = unicor_time_utils.parse_rfc3339_ns(match['timestamp'])
                except ValueError:
                    logger.warning("Unable to digest timestamp: {}".format(match))

                domain = match['query']
                ips = match['answers']
            else:
                # Regular correlation
                try:
                    timestamp = unicor_time_utils.parse_rfc3339_ns(match['dnstap']["timestamp-rfc3339ns"])
                except ValueError:
                    logger.warning("Unable to digest timestamp: {}".format(match))
                domain = match['dns']['qname']
                ips = match['dns']['resource-records']['an']
                #logger.debug("IOC: {}".format(domain))

            answers =  ', '.join([f"{entry['rdata'].split(' ', 1)[-1]} [{entry['rdatatype']}]" for entry in ips])
            if not answers:
                answers = "Did not resolve to an IP"
            match['detection'] = f"*DNS Client*:`{match['network']['query-ip']}`\n*Query*:`{domain}`\n*Answer*: `{answers}`"
            match['url'] = ""
            match['uid'] = ""
            match['timestamp_rfc3339ns'] = timestamp.isoformat()

        # Triaging generic input. Assuming it can only be an IP or a domain?
        else:
            logger.debug("Generic mode!")
            if match.get('ioc_type') not in {"domain", "ip"}: # We only support IP or domains for now
                match['ioc_type'] = None 
            # Use the ioc_type if we have one
            if match.get('ioc_type'):
                logger.debug("{} already casted as {}".format(match['ioc'], match['ioc_type']))
                if match.get('ioc_type') == "ip":
                    ips = [{'rdata': match['ioc'], 'rdatatype': "A"}]
                if match.get('ioc_type') == "domain":    
                    domain = match['ioc']
                
            # We have no ioc_type, let's guess
            else:
                # Check if 'ioc' looks like an IP. If not, it must be a domain, right?
                try:
                    testip = netaddr.IPAddress(match['ioc'])
                    logger.debug("Found an IOC IP address: {}".format(match['ioc']))
                    if testip.version == 4:
                        rdatatype = "A"
                    else:
                        rdatatype = "AAAA"
                    ips = [{'rdata': match['ioc'], 'rdatatype': rdatatype}]
                    match['ioc_type'] = "ip"
                except ValueError:
                    logger.debug("Found an IOC domain: {}".format(match['ioc']))
                    domain = match['ioc']
                    match['ioc_type'] = "domain"
            try:
                timestamp = unicor_time_utils.parse_rfc3339_ns(match['timestamp_rfc3339ns'])
            except ValueError:
                logger.warning("Unable to digest timestamp: {}".format(match))

        # Signal we have a new domain or IP alert to send from one of the input files
                
        if domain:
            if correlate_domain(domain, domain_attributes):
                match['ioc'] = domain if not match.get('ioc') else match['ioc']
                logger.debug("Adding domain IOC: {}".format(match['ioc']))
                match['ioc_type'] = "domain"
                total_matches.append(match) 

        for ip_structure in ips:
            #logger.debug("This is my IP: {}".format(ip_structure))
            if correlate_ip(ip_structure, ip_attributes):
                match['ioc'] = ip_structure['rdata'] if not match.get('ioc') else match['ioc']
                match['ioc_type'] = "ip"
                if ip_attributes_metadata: # retro mode
                    total_matches.append(match)
                    continue
                else:
                    total_matches.append(match)
                break       

    return total_matches

def correlate_file(file_iter, domain_attributes, ip_attributes, domain_attributes_metadata, ip_attributes_metadata, is_minified):
    total_matches = []
    total_matches = correlate_events(file_iter, (domain_attributes, ip_attributes, domain_attributes_metadata, ip_attributes_metadata, is_minified))
    return total_matches

