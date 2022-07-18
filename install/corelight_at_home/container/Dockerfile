FROM debian@sha256:b7143e59988c0fc41d7f77a6842a18a191433a5124e9f12c1f4fb1232b8768c5

RUN \
  apt update && \
  apt -y install git gnupg2 lsb-release file curl wget python3-pip

COPY apt-auth-corelight-softsensor.conf /etc/apt/auth.conf.d/corelight-softsensor.conf
COPY apt-sources-corelight-softsensor.conf /etc/apt/sources.list.d/corelight-softsensor.list
COPY corelight-license.txt /etc/corelight-license.txt
COPY corelight-softsensor.conf /etc/corelight-softsensor.conf

# TODO - GeoIP stuff

RUN pip3 install suricata-update && \
  suricata-update update-sources --suricata-conf=/var/corelight/suricata/.suricata.yaml --suricata=/opt/corelight/bin/suricata -D /etc/corelight/suricata-update && \
  touch /etc/corelight/suricata-update/enable.conf /etc/corelight/suricata-update/disable.conf /etc/corelight/suricata-update/modify.conf /etc/corelight/suricata-update/custom_rules && \
  suricata-update \
    --disable-conf=/etc/corelight/suricata-update/disable.conf \
    --modify-conf=/etc/corelight/suricata-update/modify.conf \
    --enable-conf=/etc/corelight/suricata-update/enable.conf \
    --suricata-conf=/var/corelight/suricata/.suricata.yaml \
    --suricata=/opt/corelight/bin/suricata -D \
    /etc/corelight/suricata-update -o \
    /etc/corelight/rules \
    --local=/etc/corelight/suricata-update/custom_rules --no-test && \
  wget -qO - https://pkgs.corelight.com/signing.pub | apt-key add - && \
  apt update && \
  apt -y install corelight-softsensor
