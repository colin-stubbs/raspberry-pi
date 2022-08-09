# NOTE

Make sure eth0 offloading features are disabled outside of the container, as even with host based networking it doesn't appear to be able to do it?

e.g. something like this in /etc/rc.local,

```
root@corelight:/opt/docker/compose/corelight# cat /etc/rc.local
#!/bin/sh -e
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

ifconfig eth0 inet 0.0.0.0 up

ethtool -K eth0 tx-checksum-ip-generic off
ethtool -K eth0 generic-segmentation-offload off
ethtool -K eth0 generic-receive-offload off

exit 0
root@corelight:/opt/docker/compose/corelight#
```

# Build

```
root@corelight:/opt/docker/compose/corelight# sh build.sh
No stopped containers
[+] Building 166.4s (9/9) FINISHED
 => [internal] load build definition from Dockerfile                                                                                                                                                                                               0.0s
 => => transferring dockerfile: 2.56kB                                                                                                                                                                                                             0.0s
 => [internal] load .dockerignore                                                                                                                                                                                                                  0.0s
 => => transferring context: 2B                                                                                                                                                                                                                    0.0s
 => [internal] load metadata for docker.io/library/debian:bullseye                                                                                                                                                                                 1.9s
 => [1/4] FROM docker.io/library/debian:bullseye@sha256:82bab30ed448b8e2509aabe21f40f0607d905b7fd0dec72802627a20274eba55                                                                                                                          10.8s
 => => resolve docker.io/library/debian:bullseye@sha256:82bab30ed448b8e2509aabe21f40f0607d905b7fd0dec72802627a20274eba55                                                                                                                           0.0s
 => => sha256:82bab30ed448b8e2509aabe21f40f0607d905b7fd0dec72802627a20274eba55 1.85kB / 1.85kB                                                                                                                                                     0.0s
 => => sha256:ede74d90543e4dedd6662653de639d72e82640717f99041591dc9f34c186f0f9 529B / 529B                                                                                                                                                         0.0s
 => => sha256:585393df054ae3733a18ba06108b2cee169be81198dde54e073526e856ff9a01 1.48kB / 1.48kB                                                                                                                                                     0.0s
 => => sha256:114ba63dd73a866ac1bb59fe594dfd218f44ac9b4fa4b2c68499da5584fcfa9d 53.68MB / 53.68MB                                                                                                                                                   4.7s
 => => extracting sha256:114ba63dd73a866ac1bb59fe594dfd218f44ac9b4fa4b2c68499da5584fcfa9d                                                                                                                                                          5.7s
 => [internal] load build context                                                                                                                                                                                                                  0.0s
 => => transferring context: 2.23kB                                                                                                                                                                                                                0.0s
 => [2/4] COPY geoipupdate.sh /usr/bin/geoipupdate                                                                                                                                                                                                 0.8s
 => [3/4] COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint                                                                                                                                                                               0.1s
 => [4/4] RUN echo "### Update GeoIP databases" &&   apt update && apt -y install wget &&   chmod 0755 /usr/bin/geoipupdate &&   /usr/bin/geoipupdate &&   apt -y install git gnupg2 lsb-rele  131.8s
 => exporting to image                                                                                                                                                                                                                            20.8s
 => => exporting layers                                                                                                                                                                                                                           20.8s
 => => writing image sha256:403963509724f81efcd071e3cc4ebdc4d42d1fd05f788da4818c771a6a799ae9                                                                                                                                                       0.0s
 => => naming to docker.io/colin-stubbs/corelight:latest                                                                                                                                                                                           0.0s
root@corelight:/opt/docker/compose/corelight# 
```

# Run

```
root@corelight:/opt/docker/compose/corelight# sh up.sh --detach
[+] Running 1/1
 ⠿ Container corelight-corelight-1  Started                                                                                                                                                                                                        0.2s
root@corelight:/opt/docker/compose/corelight# docker ps
CONTAINER ID   IMAGE                           COMMAND                  CREATED         STATUS         PORTS     NAMES
58977f243939   colin-stubbs/corelight:latest   "/bin/sh -c /usr/loc…"   3 minutes ago   Up 4 seconds             corelight-corelight-1
root@corelight:/opt/docker/compose/corelight# docker logs -t 58977f243939
2022-08-09T22:33:56.739582622Z supervisor: Licensed to corelighthome until 2023-06-13 00:00:00 UTC
2022-08-09T22:33:56.759544810Z Starting Corelight Software Sensor...
2022-08-09T22:33:56.856090495Z     Failed to disable offloading
2022-08-09T22:33:56.856453564Z     Failed to bring up interface
2022-08-09T22:33:56.856597211Z supervisor: Disabling hardware features on eth0 and bringing up the interface...done
2022-08-09T22:33:58.672213586Z suricata: This is Suricata version 6.0.5-corelight RELEASE running in SYSTEM mode
2022-08-09T22:33:58.674408445Z suricata: Preparing unexpected signal handling
2022-08-09T22:33:59.671984077Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3 support is not enabled
2022-08-09T22:33:59.755840419Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET JA3 Hash - Suspected Cobalt Strike Malleable C2 M1 (set)"; flow:established,to_server; ja3.hash; content:"eb88d0b3e1961a0562f006e5ce2a0b87"; ja3.string; content:"771,49192-49191-49172-49171"; flowbits:set,ET.cobaltstrike.ja3; flowbits:noalert; classtype:command-and-control; sid:2028831; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2019_10_15, deployment Perimeter, former_category JA3, malware_family Cobalt_Strike, signature_severity Major, updated_at 2019_10_15, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1001, mitre_technique_name Data_Obfuscation;)" from file /etc/corelight/rules/suricata.rules at line 8602
2022-08-09T22:33:59.757097587Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3(s) support is not enabled
2022-08-09T22:33:59.806356721Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET JA3 HASH - Possible RustyBuer Server Response"; flowbits:isset,ET.rustybuer; ja3s.hash; content:"f6dfdd25d1522e4e1c7cd09bd37ce619"; reference:md5,ea98a9d6ca6f5b2a0820303a1d327593; classtype:bad-unknown; sid:2032960; rev:1; metadata:attack_target Client_Endpoint, created_at 2021_05_13, deployment Perimeter, former_category JA3, malware_family RustyBuer, performance_impact Low, signature_severity Major, updated_at 2021_05_13;)" from file /etc/corelight/rules/suricata.rules at line 8727
2022-08-09T22:33:59.809236089Z supervisor: Running 4 Zeek workers.
2022-08-09T22:34:05.676002116Z suricata: 1 rule files processed. 27271 rules successfully loaded, 131 rules failed
2022-08-09T22:34:05.677005843Z suricata: Threshold config parsed: 0 rule(s) found
2022-08-09T22:34:07.677907627Z suricata: 27274 signatures processed. 1236 are IP-only rules, 5126 are inspecting packet payload, 20885 inspect application layer, 0 are decoder event only
2022-08-09T22:34:11.681345347Z manager: Loading license from environment variable
2022-08-09T22:34:11.685967617Z manager: rdp-inference-server-wl.txt/Input::READER_ASCII: Could not read input data file /etc/corelight/input_files/rdp-inference-server-wl.txt; first line could not be read
2022-08-09T22:34:11.689231183Z manager: ssh-inference-server-wl.txt/Input::READER_ASCII: Could not read input data file /etc/corelight/input_files/ssh-inference-server-wl.txt; first line could not be read
2022-08-09T22:34:11.690187133Z manager: stepping-stone-server-wl.txt/Input::READER_ASCII: Could not read input data file /etc/corelight/input_files/stepping-stone-server-wl.txt; first line could not be read
2022-08-09T22:34:11.692765023Z manager: error in /builtin/base/frameworks/broker/log.zeek, line 83: Broker error (Broker::PEER_UNAVAILABLE): (invalid-node, *127.0.0.1:27762, "unable to connect to remote peer")
2022-08-09T22:34:11.694448277Z manager: /etc/corelight/intel/zeek.intel/Input::READER_ASCII: Did not find requested field indicator in input data file /etc/corelight/intel/zeek.intel.
2022-08-09T22:34:13.702431676Z logger: Rotated/postprocessed leftover log 'broker.log' -> 'broker-22-08-09_00.30.23.log'
2022-08-09T22:34:13.711892101Z logger: Rotated/postprocessed leftover log 'cluster.log' -> 'cluster-22-08-09_00.30.23.log'
2022-08-09T22:34:13.712739015Z logger: Rotated/postprocessed leftover log 'reporter.log' -> 'reporter-22-08-09_00.30.23.log'
2022-08-09T22:34:13.714042238Z logger: Rotated/postprocessed leftover log 'corelight_license_capacity.log' -> 'corelight_license_capacity-22-08-09_00.30.43.log'
2022-08-09T22:34:13.714752043Z logger: Rotated/postprocessed leftover log 'suricata_zeek_stats.log' -> 'suricata_zeek_stats-22-08-09_00.31.23.log'
2022-08-09T22:34:13.715850824Z logger: Rotated/postprocessed leftover log 'conn.log' -> 'conn-22-08-09_00.31.24.log'
2022-08-09T22:34:13.715938063Z logger: Rotated/postprocessed leftover log 'weird.log' -> 'weird-22-08-09_00.31.26.log'
2022-08-09T22:34:13.716463408Z logger: Rotated/postprocessed leftover log 'ssl.log' -> 'ssl-22-08-09_00.31.28.log'
2022-08-09T22:34:13.722959707Z logger: Rotated/postprocessed leftover log 'software.log' -> 'software-22-08-09_00.31.29.log'
2022-08-09T22:34:13.724527871Z logger: Rotated/postprocessed leftover log 'unknown_mime_type_discovery.log' -> 'unknown_mime_type_discovery-22-08-09_00.31.29.log'
2022-08-09T22:34:13.726637897Z logger: Rotated/postprocessed leftover log 'files.log' -> 'files-22-08-09_00.31.29.log'
2022-08-09T22:34:13.727559625Z logger: Rotated/postprocessed leftover log 'dns.log' -> 'dns-22-08-09_00.31.30.log'
2022-08-09T22:34:13.729698484Z logger: Rotated/postprocessed leftover log 'http.log' -> 'http-22-08-09_00.31.34.log'
2022-08-09T22:34:55.727933263Z suricata: [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to set feature via ioctl for 'eth0': Operation not permitted (1)
2022-08-09T22:34:55.730720058Z suricata: all 4 packet processing threads, 5 management threads initialized, engine started.
2022-08-09T22:34:55.732815140Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#01-eth0: Operation not permitted
2022-08-09T22:34:55.734807742Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#02-eth0: Operation not permitted
2022-08-09T22:34:55.736346258Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#03-eth0: Operation not permitted
2022-08-09T22:34:55.737959920Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#04-eth0: Operation not permitted
2022-08-09T22:37:35.848523307Z supervisor: Licensed to corelighthome until 2023-06-13 00:00:00 UTC
2022-08-09T22:37:35.868384548Z Starting Corelight Software Sensor...
2022-08-09T22:37:35.957275160Z     Failed to disable offloading
2022-08-09T22:37:35.957422861Z     Failed to bring up interface
2022-08-09T22:37:35.957435639Z supervisor: Disabling hardware features on eth0 and bringing up the interface...done
2022-08-09T22:37:37.786019101Z suricata: This is Suricata version 6.0.5-corelight RELEASE running in SYSTEM mode
2022-08-09T22:37:37.788324957Z suricata: Preparing unexpected signal handling
2022-08-09T22:37:37.792595639Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3 support is not enabled
2022-08-09T22:37:37.863385114Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET JA3 Hash - Suspected Cobalt Strike Malleable C2 M1 (set)"; flow:established,to_server; ja3.hash; content:"eb88d0b3e1961a0562f006e5ce2a0b87"; ja3.string; content:"771,49192-49191-49172-49171"; flowbits:set,ET.cobaltstrike.ja3; flowbits:noalert; classtype:command-and-control; sid:2028831; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2019_10_15, deployment Perimeter, former_category JA3, malware_family Cobalt_Strike, signature_severity Major, updated_at 2019_10_15, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1001, mitre_technique_name Data_Obfuscation;)" from file /etc/corelight/rules/suricata.rules at line 8602
2022-08-09T22:37:37.864424710Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3(s) support is not enabled
2022-08-09T22:37:37.891999492Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET JA3 HASH - Possible RustyBuer Server Response"; flowbits:isset,ET.rustybuer; ja3s.hash; content:"f6dfdd25d1522e4e1c7cd09bd37ce619"; reference:md5,ea98a9d6ca6f5b2a0820303a1d327593; classtype:bad-unknown; sid:2032960; rev:1; metadata:attack_target Client_Endpoint, created_at 2021_05_13, deployment Perimeter, former_category JA3, malware_family RustyBuer, performance_impact Low, signature_severity Major, updated_at 2021_05_13;)" from file /etc/corelight/rules/suricata.rules at line 8727
2022-08-09T22:37:38.892663952Z supervisor: Running 4 Zeek workers.
2022-08-09T22:37:42.786317901Z suricata: 1 rule files processed. 27271 rules successfully loaded, 131 rules failed
2022-08-09T22:37:44.405313689Z suricata: Threshold config parsed: 0 rule(s) found
root@corelight:/opt/docker/compose/corelight#
```
