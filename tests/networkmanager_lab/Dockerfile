FROM debian:12-slim

RUN apt-get -o Acquire::ForceIPv4=true \
        -o Acquire::http::Timeout=20 \
        -o Acquire::Retries=2 update \
    && DEBIAN_FRONTEND=noninteractive apt-get \
        -o Acquire::ForceIPv4=true \
        -o Acquire::http::Timeout=20 \
        -o Acquire::Retries=2 install -y --no-install-recommends \
        dbus \
        dnsmasq-base \
        iproute2 \
        iputils-ping \
        network-manager \
        udev \
    && rm -rf /var/lib/apt/lists/*

COPY run-lab.sh /usr/local/bin/run-sgx-nm-lab

ENTRYPOINT ["/usr/local/bin/run-sgx-nm-lab"]
