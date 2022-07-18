FROM debian@sha256:b7143e59988c0fc41d7f77a6842a18a191433a5124e9f12c1f4fb1232b8768c5

RUN apt update && \
  apt -y install git gnupg2 lsb-release file curl wget

COPY apt-auth-corelight-softsensor.conf /etc/apt/auth.conf.d/corelight-softsensor.conf
COPY apt-sources-corelight-softsensor.conf /etc/apt/sources.list.d/corelight-softsensor.list
COPY corelight-license.txt /etc/corelight-license.txt
COPY corelight-softsensor.conf /etc/corelight-softsensor.conf

RUN wget -qO - https://pkgs.corelight.com/signing.pub | apt-key add - && \
  apt -y install corelight-softsensor
