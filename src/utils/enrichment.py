from cachetools import cached
from cachetools.keys import hashkey
import logging

logger = logging.getLogger("unicorcli")

@cached(cache={}, key=lambda misp_connection, args, value, types: hashkey(misp_connection.root_url, value, tuple(types)))
def query_misp(misp_connection, args, value, types):
    r = misp_connection.search(
        controller="attributes",
        value=value,
        include_context=True,
        type_attribute=types,
        include_correlations=False,
        pythonify=True,
        debug=False,
        to_ids=True,
        include_event_tags=True,
        **args
    )

    return r

def build_misp_events(misp_response, misp_connection, encountered_events, query):
    misp_events = []

    for attribute in misp_response:
        event = attribute.Event
        if not event.uuid in encountered_events:
            tags = []
            for tag in attribute.tags:
                tags.append(
                    {
                        "colour": tag.colour,
                        "name": tag.name
                    }
                )

            misp_events.append(
                {
                    'uuid': event.uuid,
                    'info': event.info,
                    'id': event.id,
                    'server': misp_connection.root_url,
                    'event_url': "{}/events/view/{}".format(misp_connection.root_url, event.id),
                    #'num_iocs': event.attribute_count,
                    'publication': event.date.strftime("%Y-%m-%d"),
                    'organization': event.Orgc.name,
                    'comment': attribute.comment,
                    'tags': tags,
                    'ioc': attribute.value,
                    'ioc_type': attribute.type
                }
            )

            encountered_events.add(event.uuid)

    return misp_events, encountered_events


def enrich_logs(logs, misp_connections, is_minified):
    enriched_results = []
       
    for log in logs:
        
        ips = []
        domain = ""
        ioc = ""
        # Triage the IOC type, between dnstap, domain or IP
        
        # dnstap data format
        if log.get('ioc_type') == "dns":
            if is_minified:
                domain = log['query']
                ips = log['answers']
                timestamp = log['timestamp']
                query_ip = log['client']
                client_id = log['client_id']
            else:
                domain = log['dns']['qname']
                ips = log['dns']['resource-records']['an']
                timestamp = log['dnstap']['timestamp-rfc3339ns']
                query_ip = log['network']['query-ip']
                client_id = log['dnstap']['identity']
            
            answers =  ', '.join([f"{entry['rdata'].split(' ', 1)[-1]} [{entry['rdatatype']}]" for entry in ips])
            if not answers:
                answers = "No answer"
            detection = f"*DNS Client*:`{query_ip}`\n*Query*:`{domain}`\n*Answer*: `{answers}`"


        # Generic mode
        else:
            timestamp = log['timestamp_rfc3339ns']
            detection = log['detection']
            ioc = log['ioc']
            if log.get('ioc_type') == "domain":
                domain = log['ioc']
            if log.get('ioc_type') == "dns":
                ips = log['ioc']

    # Now we know what domains and/or IPs we need to look up in MISP
        misp_events = []
        encountered_events = set()
        for misp_connection, args in misp_connections:
            if domain:
                # Search for domain
                r = query_misp(misp_connection, args, domain, ['domain', 'domain|ip', 'hostname', 'hostname|port'])

                domain_events, encountered_events = build_misp_events(
                    r,
                    misp_connection,
                    encountered_events,
                    domain
                )
                misp_events.extend(domain_events)

            # Search for each ip
            for ip_structure in ips:
                # Flatten the ip formatting (A, AAAA, string)
                if isinstance(ip_structure, dict):
                    # If the rdatatype is an IP, let's use it
                    if ip_structure.get('rdatatype') in ('A', 'AAAA'):
                        ip = ip_structure.get('rdata', "")  # Assigns the IP string if available, else empty string
                    # If the rdatatype is something else like MX, let's bail out
                    else:
                        ip = ""
                # So if the IP is not in dnstap format with rdatatype, it's gotta be a string
                else:
                    ip = ip_structure  # Keeps the original format if it's not A/AAAA
                    
                if ip:
                    # We have an actual IP, let's dig it up in MISP
                    r = query_misp(
                        misp_connection,
                        args,
                        ip,
                        [
                            'domain',
                            'domain|ip',
                            'hostname',
                            'hostname|port',
                            'ip-src',
                            'ip-src|port',
                            'ip-dst',
                            'ip-dst|port'
                        ]
                    )

                    ip_events, encountered_events = build_misp_events(
                        r,
                        misp_connection,
                        encountered_events,
                        ip
                    )
                    misp_events.extend(ip_events)

        
        if not ioc:
                ioc = misp_events[0].get('ioc') if len(misp_events) > 0 else None
        if not ioc:
                ioc = "No IOC found"
        enriched_results.append(
            {
                "timestamp": timestamp,
                "ioc": ioc,
                "detection": detection,
                "correlation": {
                    "misp": {
                        "events": misp_events
                    }
                }
            }
        )


    return enriched_results
