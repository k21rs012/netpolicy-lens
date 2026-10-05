FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 python3 python3-pexpect python3-scapy ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
ARG CHR_VERSION=7.23.7
RUN curl --fail --location --retry 2 "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip" -o /tmp/chr.zip && unzip /tmp/chr.zip -d /opt && mv /opt/chr-*.img /opt/chr.img && rm /tmp/chr.zip && sha256sum /opt/chr.img > /opt/chr.sha256
RUN echo "d97f5b2bb93e84bc7f7a7043cc262c9d8e8a2395055b795a36fa4acd9bc9b240  /opt/chr.img" | sha256sum -c -
WORKDIR /lab
CMD ["python3", "/lab/chr/probe.py"]
