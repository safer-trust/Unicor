## On the Unicor server: dns-collector receiver

1. Make sure Unicor is already configured and fully operational
  
2. Define the version of the `dns-collector` that you want to install:

   ```sh
    GO_DNSCOLLECTOR_VERSION=$(curl -s https://api.github.com/repos/dmachard/dns-collector/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//')
   ```

3. Install `dns-collector`

    ```sh
    curl -LO  "https://github.com/dmachard/dns-collector/releases/download/v${GO_DNSCOLLECTOR_VERSION}/dns-collector_${GO_DNSCOLLECTOR_VERSION}_linux_amd64.tar.gz" && \
    tar xvf "dns-collector_${GO_DNSCOLLECTOR_VERSION}_linux_amd64.tar.gz" && \
    mv dns-collector /usr/bin/
    ```
4. Adjust the permissions for the user and create the directories needed to be able to run `dns-collector`:

    ```sh
    chmod +x /usr/bin/dns-collector
    chcon -t bin_t /usr/bin/dns-collector
    setcap cap_net_raw+ep /usr/bin/dns-collector
    chown unicor:unicor /usr/bin/dns-collector
    ```

5. Adjust the configuration file, which is automatically generated as config.yml using the following templates:

    ```sh
    mkdir -p /etc/dnscollector 
    curl -o /etc/dnscollector/config.yml https://raw.githubusercontent.com/safer-trust/unicor/refs/heads/main/config/dnscollector.yml
    chown -R unicor:unicor /etc/dnscollector/
    chmod -R u+rw /etc/dnscollector/ 
    vi /etc/dnscollector/config.yml
    ```
 
6. Test the configuration file to make sure it doesn't have typos:

    ```sh
    dns-collector -config /etc/dnscollector/config.yml -test-config
    ```
7. Execute the collector:

Configure the collector as a service

   ```sh
    curl -o /etc/systemd/system/dnscollector.service https://raw.githubusercontent.com/safer-trust/unicor/refs/heads/main/config/dnscollector.service
    systemctl daemon-reload
    systemctl start dnscollector
    systemctl enable dnscollector
   ```

For debugging purposes, it is possible to start `dns-collector` manually 

   ```sh
    dns-collector -config /etc/dnscollector/config.yml
   ```

8. Ensure that the collecting port set in the configuration file is accessible and the port open. For example:
    ```sh
    sudo firewall-cmd --zone=public --add-port=7001/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=7001/udp --permanent
    sudo firewall-cmd --reload
    ```



## On the DNS server: dns-collector sender

1. Create the user that will run the service:
    ```sh
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin dnscollector
    ```
2. Define the version of the `dns-collector` that you want to install:

   ```sh
    GO_DNSCOLLECTOR_VERSION=$(curl -s https://api.github.com/repos/dmachard/dns-collector/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//')
   ```

3. Install `dns-collector`

    ```sh
    curl -LO  "https://github.com/dmachard/dns-collector/releases/download/v${GO_DNSCOLLECTOR_VERSION}/dns-collector_${GO_DNSCOLLECTOR_VERSION}_linux_amd64.tar.gz" && \
    tar xvf "dns-collector_${GO_DNSCOLLECTOR_VERSION}_linux_amd64.tar.gz" && \
    mv dns-collector /usr/bin/
    ```
4. Adjust the permissions for the user and create the directories needed to be able to run `dns-collector`:

    ```sh
    chmod +x /usr/bin/dns-collector
    chcon -t bin_t /usr/bin/dns-collector
    setcap cap_net_raw+ep /usr/bin/dns-collector
    chown dnscollector:dnscollector /usr/bin/dns-collector

    mkdir -p /var/dnscollector
    chown -R dnscollector:dnscollector /var/dnscollector/
    chmod -R u+rw /var/dnscollector/
    ```

5. Adjust the configuration file, which is automatically generated as config.yml using the following templates:

    ```sh
    mkdir -p /etc/dnscollector 
    curl -o /etc/dnscollector/config.yml https://raw.githubusercontent.com/safer-trust/unicor/refs/heads/main/config/dnscollector-sender.yml
    chown -R dnscollector:dnscollector /etc/dnscollector/
    chmod -R u+rw /etc/dnscollector/ 
    vi /etc/dnscollector/config.yml
    ```
 
6. Test the configuration file to make sure it doesn't have typos:

    ```sh
    dns-collector -config /etc/dnscollector/config.yml -test-config
    ```
7. Execute the collector:

Configure the collector as a servicee:

   ```sh
    curl -o /etc/systemd/system/dnscollector.service  https://raw.githubusercontent.com/safer-trust/unicor/refs/heads/main/config/dnscollector.service
    systemctl daemon-reload
    systemctl start dnscollector
    systemctl enable dnscollector
   ```

For debugging purposes, it is possible to start `dns-collector` manually 

   ```sh
    dns-collector -config /etc/dnscollector/config.yml
   ```


## Testing and debugging DNS-collector

* Check if the service is running and its logs:

```sh
# systemctl status dnscollector
# journalctl -u dnscollector -f
```

* Check if the process is running:
```sh
# ps -aux | grep dnscollector
dnscoll+   37571  0.0  1.1 1395372 40108 ?       Ssl  May23   2:03 /usr/bin/dns-collector -c /etc/dnscollector/config.yml
```
* Check if the connection has been established. We will use the port [7001](../tree/main/config/dnscollector/server.yml#L21) as example:

    A. From the DNS sensor:
    ```sh
    # netstat -putan | grep 7001
    tcp        0      0 IP_DNS:59450            IP_Unicor:7001         ESTABLISHED 37571/go-dnscollect 
    ```
    B. From Unicor:
    ```sh
    # netstat -putan | grep 7001
    tcp6       0      0 :::7001                 :::*                    LISTEN      19378/go-dnscollect 
    tcp6       0      0 IP_Unicor:7001         IP_DNS:59450            ESTABLISHED 19378/go-dnscollect
    ```
* Check if the Unicor collector is receiving logs:
```sh
# tail /var/unicor/queries.json
# tcpdump -i eth0 -A port 7001
```

### DNS Server (for testing)

To set up a test environment, you can easily deploy a Bind9 DNS server by following the steps outlined below. Please note that the provided template and installation instructions are intended for testing purposes only and are **NOT** suitable for a production environment. For best practices and production setups, please refer to the [Official Documentation](https://kb.isc.org/docs/bind-best-practices-recursive).

1. Install Bind9 
    ```sh
    dnf copr enable isc/bind
    yum install isc-bind
    ```
2. Create log directory and edit the `name.conf` file using the [template](../tree/main/config/test_lab/named.conf)
    ```sh
    mkdir -p /var/log/named 
    chown named:named /var/log/named 
    curl -o /etc/opt/isc/scls/isc-bind/named.conf https://raw.githubusercontent.com/CERN-CERT/pDNSSOC/main/config/test_lab/named.conf
    vim /etc/opt/isc/scls/isc-bind/named.conf
    chown named:named /etc/opt/isc/scls/isc-bind/named.conf
    sudo -u named /opt/isc/isc-bind/root/usr/bin/named-checkconf /etc/opt/isc/scls/isc-bind/named.conf
    ```
3. Start and enable the DNS service
    ```sh
    systemctl start isc-bind-named
    systemctl enable isc-bind-named
    systemctl status isc-bind-named
    ```
4. Open the internal firewall if you want to resolve domains from other instances
    ```sh
    systemctl start firewalld
    systemctl enable firewalld
    firewall-cmd --permanent --add-service=dns
    firewall-cmd --reload
    firewall-cmd --list-all
    ```
### Test installation

* Check that the DNS can resolve domains. 
```sh
host1# dig @IP_DNS maliciousdomain.com
dns# /opt/isc/isc-bind/root/usr/bin/dnstap-read /var/log/named/dnstap.log 
27-May-2024 17:57:01.255 CQ IP_HOST1:47263 -> IP_DNS:53 UDP 49b maliciousdomain.com/IN/A
```
