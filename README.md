# Unicor

<picture>
  <img src="unicor.png" alt="Unicor logo" width="30%" align="right">
</picture>


**Unicor is a generic correlation and alerting engine, matching MISP events against JSON input from a variety of sources.**

Sources include `dnstap` with [DNS-collector](https://github.com/dmachard/DNS-collector) or any JSON source in the [Unicor schema](#unicor-json-schema) and include Zeek, Netflow alerts and more.

Unicor does retro-searches too, it will go back to previously ingested data and attempt to match it again against more recently added MISP events.

Unicor is the successor of [pDNSSOC](https://github.com/safer-trust/pdnssoc-cli), and is proudly supported by [SAFER](https://safer-trust.org) members.

## Installation summary

A complete Unicor installation only requires:
  1. Access to a MISP instance (URL + API key are required)
  2. A source of data, for example:
  - `dnstap` files (typically rsync'ed via SSH) and a local [DNS-collector](https://github.com/dmachard/DNS-collector)
  - Any source (Zeek, etc.) producing files in the [Unicor JSON schema](#unicor-json-schema)
  4. A destination for alerts: Webhooks like Slack are highly recommended, or email (deprecated)

The installation guide will focus first on deploying and configuring Unicor, then provide configuration examples for different input sources.

An example `dnstap` alert in Slack:

<picture>
  <img src="unicor_alert.png" alt="Unicor alert example" width="50%">
</picture>


## Installation guide

### Installing Unicor

#### Binary installation
The recommended installation path is to use a binary form of Unicor, produced by PyInstaller.

(It may be necessary to install dependencies and specifically reference PyMISP)
```
git clone https://github.com/safer-trust/unicor.git
cd unicor/src/
pyinstaller  --add-binary="/usr/local/lib/python3.9/dist-packages/pymisp:pymisp" -F  unicor.py
```
Then the binary will be readily available:
```
 ./dist/unicor 
Usage: unicor [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config FILE  Read option defaults from the specified yaml file
                     [default: /etc/unicor/config.yml]
  --help             Show this message and exit.

Commands:
  alert       Raise alerts for spotted incidents
  correlate   Correlate input files and output matches
  fetch-iocs  Fetch IOCs from intelligence sources
```
A ELF 64-bit dynamically linked version is also directly available in the [dist directory](https://github.com/safer-trust/unicor/tree/main/src/dist) of the repository.

Move the binary in one of the executable PATH, for example:

  ```sh
  sudo mv ./dist/unicor /usr/local/bin/
  ```

### Configuring Unicor

#### Filesystem preparation

Create the relevant user, files and directories, and assign permissions:

    ```sh
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin unicor
    mkdir -p /var/unicor /var/dnscollector/alerts /var/unicor/queries /var/unicor/matches
    touch /var/unicor/alerts/matches.json /var/unicor/misp_ips.txt /var/unicor/misp_domains.txt /var/unicor/queries/queries.json /var/unicor/alerts_db.txt /var/unicor/matches/matches_domains.json /var/unicor/matches/matches_ips.json
    chown -R unicor:unicor /var/unicor/
    chmod -R u+rw /var/unicor/
    sudo mkdir /etc/unicor
    ```

#### Configuration file & CRON

- Create the Unicor configuration file (`config.yml`) under `/etc/unicor/`, based on the [Unicor template]([https://github.com/safer-trust/pdnssoc-cli/blob/main/config/pdnssoccli.yml](https://github.com/safer-trust/unicor/blob/main/config/config.yml).

   ```sh
   curl -o /etc/unicor/config.yml https://raw.githubusercontent.com/safer-trust/pdnssoc-cli/refs/heads/main/config/pdnssoccli.yml
   chown -R unicor:unicor /etc/unicor
   ```

- Modify it to add you MISP URL + API, and configure a destination output for alerts. Webhooks are recommended.
  
  ```sh
  vi /etc/unicor/config.yml
  ```

- Test your configuration file
  ```sh
  # pip install yamllint
  # yamllint /etc/unicor/config.yml
  ```

- Test the Unicor commands
  ```sh
  # sudo -u unicor unicor fetch-iocs
  # sudo -u unicor unicor correlate
  # sudo -u unicor unicor alert
  ```

- Add a CRON to run Unicor on a schedule, for example in `/etc/crontab`:

  ```
  * * * * * unicor unicor fetch-iocs  >> /var/log/unicor-fetch-iocs.log 2>&1
  * * * * * unicor unicor correlate  /var/unicor/matches >> /var/log/unicor-correlate.log 2>&1 &&  pdnssoc-cli alert  /var/unicor/alerts/ >> /var/log/unicor-alert.log 2>&1
  * * * * * unicor ([ $(awk '{print $1}' /proc/loadavg) \< 0.5 ] && unicor correlate --retro_disco_lookup /var/unicor/queries/) >> /var/log/unicor-retro.log  2>&1
  ```

### Supported sources

#### dnstap and [DNS-collector](https://github.com/dmachard/DNS-collector)

<a name="unicor-json-schema"></a>
#### input Unicor JSON 
