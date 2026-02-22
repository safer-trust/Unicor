# We'll use wolfi instead of alpine or python to keep the CVEs down.
# install system packages
FROM cgr.dev/chainguard/wolfi-base AS base
RUN \
  apk add python-3.14 py3.14-pip cronie logrotate && \
  mkdir /unicor /etc/unicor


# install python packages
FROM base AS pythonpkgs
COPY requirements.txt /unicor/requirements.txt
RUN \
  pip install -r /unicor/requirements.txt && \
  addgroup -S unicor && \
  adduser -S -G unicor -h / -s /bin/sh -D unicor



# do unicor setup
FROM pythonpkgs AS unicor
COPY src /unicor
COPY templates /unicor/
COPY config/config.yml /etc/unicor/config.yml.example
COPY container /
RUN \
  rm -rf /unicor/dist && \
  chmod 755 /usr/local/bin/unicor && \
  ln -s /tmp /var/run && \

VOLUME /persistent
CMD [ "cron" ]
ENTRYPOINT [ "/entrypoint" ]



