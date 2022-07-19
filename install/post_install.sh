#!/bin/bash

apt -y install lvm2 lsof vim xfsprogs file tcpdump

echo '#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

# Print the IP address
_IP=$(hostname -I) || true
if [ "$_IP" ]; then
  printf "My IP address is %s\n" "$_IP"
fi

# corelight-softsensor
# ethtool -K eth0 tx-checksum-ip-generic off
# ethtool -K eth0 generic-segmentation-offload off
# ethtool -K eth0 generic-receive-offload off
# ifconfig eth0 inet 0.0.0.0 up

exit 0

# EOF' > /etc/rc.local

# EOF
