# Unicor

<picture>
  <img src="unicor.png" alt="Unicor logo" width="30%" align="right">
</picture>


**Unicor is a generic correlation and alerting engine, matching MISP events against JSON input from a variety of sources.**

Sources include `dnstap` with [DNS-collector](https://github.com/dmachard/DNS-collector) or any JSON source in the [Unicor schema](#unicor-json-schema) and include Zeek, Netflow alerts and more.

Unicor does retro-searches too, it can go back to older data and attempt to match it again against more recently added MISP events.

Unicor is the successor of [pDNSSOC](https://github.com/safer-trust/pdnssoc-cli), and is proudly supported by [SAFER](https://safer-trust.org) members.

## Usage

```
Usage: unicor [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config FILE  Read option defaults from the specified yaml file
                     [default: /etc/unicor/config.yml]
  --help             Show this message and exit.

Commands:
  fetch-iocs                      Fetch IOCs from MISP, typically domains and IPs
  correlate                       Correlate input files and produce matches for potential alerts
  correlate --retro_disco_lookup  Reprocesses input in the list of newer MISP events
  alert                           Send alerts to pre-defined destinations like Slack
```

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

### 1. Installing Unicor

#### 1.1 Binary installation
The recommended installation path is to use a binary form of Unicor, produced by PyInstaller.

The easiest way to get a binary x86_64 Unicor is:

 ```sh
 sudo curl -Lo /usr/local/bin/unicor https://github.com/safer-trust/Unicor/raw/refs/heads/main/src/dist/unicor
 chmod +x /usr/local/bin/unicor
 ```

It is recommended to compile it on the local system from the repository as follows.

(It may be necessary to install dependencies and specifically reference PyMISP)
```
pip install pyinstaller
git clone https://github.com/safer-trust/unicor.git
cd unicor/
pip install -r requirements.txt
src/
PYMISP_PATH=$(python3 -c "import pymisp, os; print(os.path.dirname(pymisp.__file__))")
sed -i "s|('\([^']*\)/pymisp', 'pymisp')|('$PYMISP_PATH', 'pymisp')|g" unicor.spec
pyinstaller unicor.spec
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
sudo cp ./dist/unicor /usr/local/bin/
```


#### 1.2 Repo installation

This is not recommended and may result in a number of issues with Python dependencies, paths, or venv mishaps, and cause personal injury or illness.

```
git clone https://github.com/safer-trust/unicor.git
cd unicor/
pip install -r requirements.txt
cd src
python3 -m unicor
```

For compatibility with the rest of this guide, it is also necessary to create a script executing `python3 -m unicor`, available in $PATH.
For example, a Bash or Python script in `/usr/local/bin/unicor`:

```
cd src/
sudo bash -c 'echo -e "#!/bin/bash\ncd \"$(pwd)\"\npython3 -m unicor \"\$@\"" > /usr/local/bin/unicor && chmod +x /usr/local/bin/unicor'
```

### 2. Configuring Unicor

#### 2.1 Filesystem preparation

Create the relevant user, files and directories, and assign permissions:

  ```sh
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin unicor
  mkdir -p /var/unicor /var/unicor/alerts /var/unicor/queries /var/unicor/matches
  touch /var/unicor/alerts/matches.json /var/unicor/misp_ips.txt /var/unicor/misp_domains.txt /var/unicor/queries/queries.json /var/unicor/alerts_db.txt /var/unicor/matches/matches_domains.json /var/unicor/matches/matches_ips.json
  chown -R unicor:unicor /var/unicor/
  chmod -R u+rw /var/unicor/
  sudo mkdir /etc/unicor
  ```

#### 2.2 Configuration file & CRON

- Create the Unicor configuration file (`config.yml`) under `/etc/unicor/`, based on the [Unicor template](https://raw.githubusercontent.com/safer-trust/unicor/refs/heads/main/config/config.yml](https://raw.githubusercontent.com/safer-trust/unicor/refs/heads/main/config/config.yml).

   ```sh
   mkdir -p /etc/unicor/
   curl -Lo /etc/unicor/config.yml https://raw.githubusercontent.com/safer-trust/unicor/refs/heads/main/config/config.yml
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
  # sudo -u unicor /usr/local/bin/unicor fetch-iocs
  # sudo -u unicor /usr/local/bin/unicor correlate
  # sudo -u unicor /usr/local/bin/unicor alert
  ```
- Using self-signed certificates or other CA Bundles
In case it is imperative to use a self-signed certificate with MISP, or an alternative CA bundle, for example for testing, it is possible to pass on a path to the certificate and maintain a TLS connection:

```
CURL_CA_BUNDLE=/var/containers/misp-jisc/persistent/misp/tls/misp.crt /usr/local/bin/unicor fetch-iocs
```
For installations from the repo, it is recommended to add the `CURL_CA_BUNDLE` variable directly in `/usr/local/bin`

- Add a CRON to run Unicor on a schedule, for example in `/etc/crontab`:

  ```
  * * * * * unicor /usr/local/bin/unicor fetch-iocs  >> /var/log/unicor-fetch-iocs.log 2>&1
  * * * * * unicor /usr/local/bin/unicor correlate  /var/unicor/matches >> /var/log/unicor-correlate.log 2>&1 && /usr/local/bin/unicor alert /var/unicor/alerts/ >> /var/log/unicor-alert.log 2>&1
  ```

With the log files:
  ```
  touch /var/log/unicor-alert.log /var/log/unicor-fetch-iocs.log /var/log/unicor-correlate.log
  chown unicor /var/log/unicor-*
  ```

- Optional: Enable retro-searches

Unicor can reprocess and re-correlate JSON input as new MISP events are added.
  1. Create a dedicated directory owned by the `unicor` user to add JSON files.
  For example: `mkdir /var/unicor/archive/ && chown -R unicor:unicor /var/unicor/archive/`
  4. Add another CRON to run retro-searches on a schedule, for example in `/etc/crontab`:

  ```
    * * * * * unicor ([ $(awk '{print $1}' /proc/loadavg) \< 0.5 ] && /usr/local/bin/unicor correlate /var/unicor/archive/) >> /var/log/unicor-retro.log  2>&1
  ```

The main use case here is `dnstap` data process with [DNS-collector](https://github.com/dmachard/DNS-collector), where a dedicated `pipelines`
to archive all DNS queries has previously been added as follows:
  ```
   - name: fileall
     logfile:
          file-path: /var/unicor/archive/queries.json
          mode: json
          flush-interval: 1
          # Tune the size and number of files used for retro searches here:
          max-size: 200
          max-files: 5
          chan-buffer-size: 65535
          postrotate-delete-success: true
  ```

Please refer to the [DNS-collector](https://github.com/dmachard/DNS-collector) configuration below for more information.


### 3. Adding supported sources

<a name="unicor-json-schema"></a>
#### 3.1 JSON input

Any data following the Unicor JSON schema can be added as a source.

JSON files must be placed with a `.json` extension in the configured `input_dir` in `/etc/unicor/config.yml`.
- The default is `/var/dnscollector/matches/`
- An example input file could be `/var/dnscollector/matches/zeek-2025-02-14.json`
- The JSON files contain **one JSON object per line**, each representing a potential alert
- Each line **must follow** the Unicor JSON schema 

Unicor JSON schema, originally in ONE LINE, but made prettier below:
  ```
  {
   "ioc": "${domain or ip}",  // domain or IP address
   "ioc_type": "${ioc_type}", // Optional field expressing the type of IOC. ioc_type can be "ip" or "domain"
   "timestamp_rfc3339ns": "${time}", 
   "detection": "${alert}", // Text or simple Markdown with the actual alert
   "uid": "${uid}", // Optional uid of the source event
   "url": "${url}", // Optional url of the source event
  }
  ```

#### 3.2 JSON input examples

With Zeek, it is recommended to use the [MISP intel policy](https://github.com/initconf/misp_intel).
Then in Unicor, `${alert}` could be: `"id.orig_h:id.orig_p -> id.resp_h:id.resp_p (seen.where)"`
Example:
  ```
  {
   "ioc": "evil.top",
   "timestamp_rfc3339ns": "2025-02-07T18:50:51.659830055Z",
   "detection": "*Connection: `188[.]184[.]21[.]197:3245` -> `123[.]345[.]123[.]456` (X509::IN_CERT)",
   "uid": "Cm8QYURGEZkdmwMFi",
  }
  ```
For netflows, a valid input could be:

  ```
  {
   "ioc": "123[.]345[.]123[.]456",
   "ioc_type": "ip",
   "timestamp_rfc3339ns": "2025-02-09T11:50:11.659830055Z",
   "detection": "*Connection: `188[.]184[.]21[.]197:3245` -> `123[.]345[.]123[.]456`\n*Bytes*: 4Kb sent, 1MB received",
   "url": "https://security-dashboard.uni.edu",
  }
  ```
#### 3.4 dnstap and [DNS-collector](https://github.com/dmachard/DNS-collector)

This is a primary use case for Unicor. 

To configure [DNS-collector](https://github.com/dmachard/DNS-collector) as a source for Unicor, follow [this detailed configuration](dns-collector-configuration.md).



