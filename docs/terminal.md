root@imx8mp-var-dart:~# echo 'alert icmp any any -> any any (msg:"SGX INLINE BLOCK TEST HIGH"; priority:1; sid:10000099; rev:1;)' >> /etc/suricata/rules/local.rules
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Suricata ko reload karo
root@imx8mp-var-dart:~# kill -USR2 $(cat /var/run/suricata.pid)
root@imx8mp-var-dart:~# sleep 5
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Ping karo trigger ke liye
root@imx8mp-var-dart:~# ping -c 3 192.168.50.1 > /dev/null
root@imx8mp-var-dart:~# sleep 8
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Check karo
root@imx8mp-var-dart:~# curl -s "http://127.0.0.1:8443/api/v1/threat/blocks" | python3 -m json.tool
{
    "blocked": []
}
root@imx8mp-var-dart:~# nft list chain inet sgx_threat input 2>/dev/null | grep -v "^}"
table inet sgx_threat {
        chain input {
                type filter hook input priority filter - 10; policy accept;
        }
root@imx8mp-var-dart:~# grep "INLINE BLOCK TEST" /var/log/suricata/fast.log | tail -3
root@imx8mp-var-dart:~# grep "10000099" /var/log/suricata/eve.json | tail -1 | python3 -m json.tool | head -10
Expecting value: line 1 column 1 (char 0)
root@imx8mp-var-dart:~# pgrep -af sgx_guardian
800319 ./sgx_guardian_client nodeA
root@imx8mp-var-dart:~# root@imx8mp-var-dart:~# nft list chain inet sgx_threat input 2>/dev/null | grep -v "^}"
root@imx8mp-var-dart:~# table inet sgx_threat {
-sh: table: command not found
root@imx8mp-var-dart:~#         chain input {
-sh: chain: command not found
root@imx8mp-var-dart:~#                 type filter hook input priority filter - 10; policy accept;
-sh: type: filter: not found
-sh: type: hook: not found
-sh: type: input: not found
-sh: type: priority: not found
-sh: type: filter: not found
-sh: type: -: not found
-sh: type: 10: not found
-sh: policy: command not found
root@imx8mp-var-dart:~#         }
-sh: syntax error near unexpected token `}'
root@imx8mp-var-dart:~# root@imx8mp-var-dart:~# grep "INLINE BLOCK TEST" /var/log/suricata/fast.log | tail -3
-sh: root@imx8mp-var-dart:~#: command not found
root@imx8mp-var-dart:~# root@imx8mp-var-dart:~# grep "10000099" /var/log/suricata/eve.json | tail -1 | python3 -m json.tool | head -10
-sh: root@imx8mp-var-dart:~#: command not found
Expecting value: line 1 column 1 (char 0)
root@imx8mp-var-dart:~# Expecting value: line 1 column 1 (char 0)
-sh: syntax error near unexpected token `('
root@imx8mp-var-dart:~# root@imx8mp-var-dart:~# pgrep -af sgx_guardian
-sh: root@imx8mp-var-dart:~#: command not found
root@imx8mp-var-dart:~# 800319 ./sgx_guardian_client
-sh: 800319: command not found
root@imx8mp-var-dart:~# echo "======================================"

ls -lah /opt/suricata/bin/suricata* 2>/dev/null || true

echo
echo "[2] Suricata version check"
suricata -V || /opt/suricata/bin/suricata -V || true

echo
echo "[3] Suricata running process check"
ps aux | grep '[s]uricata' || true

echo
echo "[4] Suricata config file present check"
ls -lah /etc/suricata/suricata.yaml || true

echo
echo "[5] Rule directories check"
ls -lah /etc/suricata/rules 2>/dev/null || true
ls -lah /var/lib/suricata/rules 2>/dev/null || true
ls -lah /opt/guardian/suricata/rules 2>/dev/null || true

echo
echo "[6] List available rule files"
find /etc/suricata /var/lib/suricata /opt/guardian -type f -name "*.rules" 2>/dev/null | sort

echo
echo "[7] Check suricata.yaml rule-files linkage"
grep -n "rule-files" -A40 /etc/suricata/suricata.yaml || true

echo
echo "[8] Check Emerging Threats / ET rules"
grep -RniE 'msg:"ET |ET ======================================
TROJAN|ET MALWARE|ET SCAN|ET EXPLOIT|ET POLICY|ET DNS|ET WEB|Emerging Threats|emerging-' \
  /etc/suricata/rules /var/lib/suricata/rules 2>/dev/null | head -60 || true

echo
echo "[9] Check Guardian / SG-X custom signatures"
grep -RniE 'SGX|Guardian|guardian|Modbus|modbus|sid:10000011|sid:1000' \
  /etc/suricata/rules /opt/guardian/suricata/rules 2>/dev/null | head -80 || true

echo
echo "[10] Final Suricata config + rules load test"
suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -80

echo "======================================"
echo "VERIFY COMPLETE"
echo "======================================"root@imx8mp-var-dart:~# echo "VERIFY: SURICATA BINARIES + RULE SETS"
VERIFY: SURICATA BINARIES + RULE SETS
root@imx8mp-var-dart:~# echo "======================================"
======================================
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[1] Suricata binary installed check"
[1] Suricata binary installed check
root@imx8mp-var-dart:~# which suricata || true
/opt/suricata/bin/suricata
root@imx8mp-var-dart:~# ls -lah /opt/suricata/bin/suricata* 2>/dev/null || true
-rwxr-xr-x 1 root root  125 Jun 16 05:52 /opt/suricata/bin/suricata
-rwxr-xr-x 1 root root 1.2K Jun 12 07:33 /opt/suricata/bin/suricata-update
-rwxr-xr-x 1 root root 5.5M Jun 12 07:33 /opt/suricata/bin/suricata.real
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[2] Suricata version check"
[2] Suricata version check
root@imx8mp-var-dart:~# suricata -V || /opt/suricata/bin/suricata -V || true
This is Suricata version 6.0.4 RELEASE
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[3] Suricata running process check"
[3] Suricata running process check
root@imx8mp-var-dart:~# ps aux | grep '[s]uricata' || true
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[4] Suricata config file present check"
[4] Suricata config file present check
root@imx8mp-var-dart:~# ls -lah /etc/suricata/suricata.yaml || true
-rw-r--r-- 1 root root 71K Jun 16 09:56 /etc/suricata/suricata.yaml
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[5] Rule directories check"
[5] Rule directories check
root@imx8mp-var-dart:~# ls -lah /etc/suricata/rules 2>/dev/null || true
total 136K
drwxr-xr-x 2 root root 4.0K Jun 16 09:56 .
drwxr-xr-x 3 root root 4.0K Jun 16 09:56 ..
-rw-r--r-- 1 root root 1.9K Nov 17  2021 app-layer-events.rules
-rw-r--r-- 1 root root  21K Nov 17  2021 decoder-events.rules
-rw-r--r-- 1 root root  468 Nov 17  2021 dhcp-events.rules
-rw-r--r-- 1 root root 1.2K Nov 17  2021 dnp3-events.rules
-rw-r--r-- 1 root root 1.1K Nov 17  2021 dns-events.rules
-rw-r--r-- 1 root root 4.0K Nov 17  2021 files.rules
-rw-r--r-- 1 root root  14K Nov 17  2021 http-events.rules
-rw-r--r-- 1 root root 2.1K Nov 17  2021 http2-events.rules
-rw-r--r-- 1 root root 2.7K Nov 17  2021 ipsec-events.rules
-rw-r--r-- 1 root root  585 Nov 17  2021 kerberos-events.rules
-rw-r--r-- 1 root root  188 Jun 18 09:21 local.rules
-rw-r--r-- 1 root root 2.1K Nov 17  2021 modbus-events.rules
-rw-r--r-- 1 root root 1.9K Nov 17  2021 mqtt-events.rules
-rw-r--r-- 1 root root  558 Nov 17  2021 nfs-events.rules
-rw-r--r-- 1 root root  558 Nov 17  2021 ntp-events.rules
-rw-r--r-- 1 root root 1.5K Nov 17  2021 smb-events.rules
-rw-r--r-- 1 root root 5.1K Nov 17  2021 smtp-events.rules
-rw-r--r-- 1 root root  13K Nov 17  2021 stream-events.rules
lrwxrwxrwx 1 root root   38 Jun 16 06:02 suricata.rules -> /var/lib/suricata/rules/suricata.rules
-rw-r--r-- 1 root root 6.8K Nov 17  2021 tls-events.rules
root@imx8mp-var-dart:~# ls -lah /var/lib/suricata/rules 2>/dev/null || true
total 42M
drwxr-xr-x 2 root root 4.0K Jun 12 07:33 .
drwxr-xr-x 4 root root 4.0K Jun 16 05:56 ..
-rw-r--r-- 1 root root 3.2K Jun 12 07:33 classification.config
-rw-r--r-- 1 root root  42M Jun 12 07:33 suricata.rules
root@imx8mp-var-dart:~# ls -lah /opt/guardian/suricata/rules 2>/dev/null || true
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[6] List available rule files"
[6] List available rule files
root@imx8mp-var-dart:~# find /etc/suricata /var/lib/suricata /opt/guardian -type f -name "*.rules" 2>/dev/null | sort
/etc/suricata/rules/app-layer-events.rules
/etc/suricata/rules/decoder-events.rules
/etc/suricata/rules/dhcp-events.rules
/etc/suricata/rules/dnp3-events.rules
/etc/suricata/rules/dns-events.rules
/etc/suricata/rules/files.rules
/etc/suricata/rules/http-events.rules
/etc/suricata/rules/http2-events.rules
/etc/suricata/rules/ipsec-events.rules
/etc/suricata/rules/kerberos-events.rules
/etc/suricata/rules/local.rules
/etc/suricata/rules/modbus-events.rules
/etc/suricata/rules/mqtt-events.rules
/etc/suricata/rules/nfs-events.rules
/etc/suricata/rules/ntp-events.rules
/etc/suricata/rules/smb-events.rules
/etc/suricata/rules/smtp-events.rules
/etc/suricata/rules/stream-events.rules
/etc/suricata/rules/tls-events.rules
/var/lib/suricata/rules/suricata.rules
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[7] Check suricata.yaml rule-files linkage"
[7] Check suricata.yaml rule-files linkage
root@imx8mp-var-dart:~# grep -n "rule-files" -A40 /etc/suricata/suricata.yaml || true
1874:rule-files:
1875-  - local.rules
1876-  - suricata.rules
1877-
1878-##
1879-## Auxiliary configuration files.
1880-##
1881-
1882-classification-file: /etc/suricata/classification.config
1883-reference-config-file: /etc/suricata/reference.config
1884-# threshold-file: /etc/suricata/threshold.config
1885-
1886-##
1887-## Include other configs
1888-##
1889-
1890-# Includes:  Files included here will be handled as if they were in-lined
1891-# in this configuration file. Files with relative pathnames will be
1892-# searched for in the same directory as this configuration file. You may
1893-# use absolute pathnames too.
1894-# You can specify more than 2 configuration files, if needed.
1895-#include: include1.yaml
1896-#include: include2.yaml
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[8] Check Emerging Threats / ET rules"
[8] Check Emerging Threats / ET rules
root@imx8mp-var-dart:~# grep -RniE 'msg:"ET |ET TROJAN|ET MALWARE|ET SCAN|ET EXPLOIT|ET POLICY|ET DNS|ET WEB|Emerging Threats|emerging-' \
>   /etc/suricata/rules /var/lib/suricata/rules 2>/dev/null | head -60 || true
/etc/suricata/rules/suricata.rules:357:alert ip $HOME_NET any -> [162.243.103.246] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 1"; reference:url,feodotracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404300; rev:7950; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Banking_Trojan, signature_severity Major, created_at 2014_11_04, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:358:alert ip $HOME_NET any -> [178.62.3.223] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 2"; reference:url,feodotracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404301; rev:7950; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Banking_Trojan, signature_severity Major, created_at 2014_11_04, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:359:alert ip $HOME_NET any -> [27.133.154.218] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 3"; reference:url,feodotracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404302; rev:7950; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Banking_Trojan, signature_severity Major, created_at 2014_11_04, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:360:alert ip $HOME_NET any -> [34.204.119.63] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 4"; reference:url,feodotracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404303; rev:7950; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Banking_Trojan, signature_severity Major, created_at 2014_11_04, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:361:alert ip $HOME_NET any -> [50.16.16.211] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 5"; reference:url,feodotracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404304; rev:7950; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Banking_Trojan, signature_severity Major, created_at 2014_11_04, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:362:alert ip [1.15.51.236,1.159.65.249,1.176.118.246,1.181.114.38,1.188.101.215,1.192.176.220,1.192.176.81,1.192.248.62,1.193.39.62,1.193.63.161,1.193.63.242,1.193.63.50,1.20.187.2,1.24.16.116,1.24.16.120,1.24.16.127,1.24.16.153,1.24.16.157,1.24.16.159,1.24.16.162,1.24.16.163,1.24.16.165,1.24.16.171,1.24.16.172,1.24.16.173,1.24.16.174,1.24.16.181,1.24.16.184,1.24.16.201,1.24.16.213,1.24.16.216,1.24.16.234,1.24.16.245,1.24.16.253,1.24.16.27,1.24.16.54,1.24.16.62,1.24.16.64,1.24.16.70,1.24.16.77,1.24.16.91,1.24.16.96,1.25.75.34,1.29.217.102,1.30.16.218,1.32.57.245,1.34.143.217,1.34.204.183,1.34.42.95,1.41.188.145] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 1"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403300; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:363:alert ip [1.54.173.163,1.83.125.11,1.83.125.132,1.83.125.137,1.83.125.14,1.83.125.187,1.83.125.20,1.83.125.237,1.83.125.243,1.83.125.255,1.83.125.43,1.83.125.48,1.83.125.51,1.83.125.81,1.83.125.91,1.83.125.95,2.136.130.81,2.157.38.89,2.176.192.111,2.181.34.210,2.189.255.143,2.26.54.120,2.26.5.94,2.26.7.24,2.27.165.137,2.27.51.108,2.27.7.107,2.40.99.114,2.50.155.215,2.50.239.81,2.55.127.38,2.58.202.29,2.86.42.248,3.131.24.55,3.142.170.60,3.68.61.17,3.83.245.221,4.144.150.30,4.150.190.180,4.213.139.55,4.227.135.146,4.227.178.194,4.227.178.208,4.227.179.79,4.227.180.232,4.230.105.204,4.246.135.163,4.246.231.57,5.101.64.6,5.135.173.212] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 2"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403301; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:364:alert ip [5.135.71.236,5.152.145.139,5.158.19.187,5.160.197.205,5.16.51.158,5.175.169.118,5.180.205.78,5.183.29.231,5.187.35.142,5.187.35.26,5.188.206.30,5.188.206.34,5.188.206.46,5.189.165.117,5.189.177.3,5.226.140.10,5.226.140.103,5.226.140.105,5.226.140.111,5.226.140.121,5.226.140.123,5.226.140.13,5.226.140.19,5.226.140.25,5.226.140.27,5.226.140.30,5.226.140.48,5.226.140.50,5.226.140.61,5.226.140.69,5.226.140.81,5.226.140.85,5.226.140.87,5.226.140.97,5.23.100.13,5.29.142.3,5.29.64.153,5.39.32.198,5.53.128.126,5.61.209.43,5.61.209.96,5.83.143.123,5.83.143.40,8.130.149.200,8.131.74.250,8.133.170.199,8.133.185.52,8.133.20.44,8.134.157.132,8.134.159.4] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 3"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403302; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:365:alert ip [8.138.154.105,8.140.211.73,8.140.218.241,8.140.225.151,8.14.63.131,8.141.100.166,8.142.178.141,8.148.200.35,8.148.81.231,8.152.99.77,8.156.83.235,8.160.182.102,8.163.67.101,8.19.75.217,8.208.10.94,8.209.100.130,8.209.100.85,8.209.101.146,8.209.101.19,8.209.101.209,8.209.101.33,8.209.105.49,8.209.107.133,8.209.107.26,8.209.108.11,8.209.108.30,8.209.108.9,8.209.109.4,8.209.109.77,8.209.110.18,8.209.112.87,8.209.113.102,8.209.114.206,8.209.114.226,8.209.114.67,8.209.115.1,8.209.115.54,8.209.116.113,8.209.116.242,8.209.119.142,8.209.119.143,8.209.124.34,8.209.125.138,8.209.126.67,8.209.126.74,8.209.127.129,8.209.127.86,8.209.196.146,8.209.197.202,8.209.200.249] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 4"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403303; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:366:alert ip [8.209.201.115,8.209.201.82,8.209.201.85,8.209.202.56,8.209.208.244,8.209.208.8,8.209.210.66,8.209.211.155,8.209.211.193,8.209.211.202,8.209.211.227,8.209.212.42,8.209.214.85,8.209.215.33,8.209.216.222,8.209.218.45,8.209.226.195,8.209.228.69,8.209.229.161,8.209.229.251,8.209.231.182,8.209.231.208,8.209.232.122,8.209.232.124,8.209.232.250,8.209.236.193,8.209.236.84,8.209.237.111,8.209.237.154,8.209.237.241,8.209.237.84,8.209.238.135,8.209.238.181,8.209.238.191,8.209.239.57,8.209.254.88,8.209.64.131,8.209.68.199,8.209.68.55,8.209.68.65,8.209.71.64,8.209.74.160,8.209.74.239,8.209.75.169,8.209.76.107,8.209.76.212,8.209.77.162,8.209.78.193,8.209.80.8,8.209.83.1] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 5"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403304; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:367:alert ip [8.209.83.42,8.209.85.215,8.209.85.27,8.209.88.128,8.209.88.212,8.209.89.108,8.209.89.121,8.209.90.19,8.209.97.111,8.209.97.27,8.210.123.17,8.210.231.235,8.210.28.151,8.211.0.173,8.211.0.98,8.211.11.111,8.211.12.141,8.211.12.163,8.211.12.171,8.211.12.213,8.211.128.112,8.211.12.88,8.211.129.87,8.211.136.6,8.211.141.140,8.211.141.81,8.211.142.197,8.211.145.50,8.211.148.150,8.211.149.145,8.211.149.255,8.211.15.153,8.211.152.146,8.211.152.223,8.211.153.10,8.211.153.127,8.211.15.33,8.211.15.4,8.211.154.230,8.211.157.244,8.211.157.94,8.211.159.236,8.211.162.191,8.211.162.225,8.211.165.58,8.211.166.117,8.211.167.32,8.211.169.222,8.211.17.103,8.211.171.136] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 6"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403305; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:368:alert ip [8.211.172.246,8.211.173.155,8.211.173.242,8.211.173.94,8.211.174.175,8.211.175.209,8.211.19.250,8.211.19.30,8.211.20.69,8.211.21.19,8.211.22.190,8.211.23.105,8.211.24.101,8.211.24.197,8.211.24.65,8.211.25.100,8.211.25.159,8.211.25.164,8.211.25.7,8.211.25.75,8.211.26.230,8.211.26.235,8.211.2.67,8.211.27.88,8.211.29.198,8.211.29.84,8.211.3.198,8.211.32.121,8.211.32.231,8.211.3.254,8.211.33.128,8.211.33.200,8.211.33.23,8.211.33.96,8.211.36.238,8.211.36.77,8.211.37.42,8.211.37.93,8.211.38.67,8.211.39.116,8.211.39.83,8.211.41.12,8.211.41.99,8.211.4.200,8.211.42.134,8.211.42.77,8.211.43.10,8.211.43.157,8.211.43.218,8.211.44.115] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 7"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403306; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:369:alert ip [8.211.44.141,8.211.44.86,8.211.45.1,8.211.45.143,8.211.45.218,8.211.45.239,8.211.46.182,8.211.46.188,8.211.46.254,8.211.46.74,8.211.46.83,8.211.47.177,8.211.47.212,8.211.47.30,8.211.47.83,8.211.5.31,8.211.7.142,8.211.7.208,8.211.7.229,8.211.8.171,8.211.8.52,8.211.9.174,8.211.9.248,8.213.229.126,8.216.0.100,8.216.0.135,8.216.0.142,8.216.0.22,8.216.0.35,8.216.0.71,8.216.10.179,8.216.10.184,8.216.10.2,8.216.10.200,8.216.10.202,8.216.10.242,8.216.10.5,8.216.10.69,8.216.11.0,8.216.11.149,8.216.11.171,8.216.11.64,8.216.11.80,8.216.12.100,8.216.12.108,8.216.12.140,8.216.12.192,8.216.12.208,8.216.12.234,8.216.1.228] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 8"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403307; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:370:alert ip [8.216.12.44,8.216.12.47,8.216.12.63,8.216.13.122,8.216.13.152,8.216.13.201,8.216.13.249,8.216.13.42,8.216.14.108,8.216.14.127,8.216.14.190,8.216.14.232,8.216.14.239,8.216.1.47,8.216.14.99,8.216.15.11,8.216.15.149,8.216.15.166,8.216.15.23,8.216.15.41,8.216.15.47,8.216.16.104,8.216.16.112,8.216.16.114,8.216.16.117,8.216.16.118,8.216.16.121,8.216.16.144,8.216.16.145,8.216.16.15,8.216.16.150,8.216.16.157,8.216.16.162,8.216.16.176,8.216.16.18,8.216.16.213,8.216.16.52,8.216.16.62,8.216.16.79,8.216.16.92,8.216.16.99,8.216.17.105,8.216.17.120,8.216.17.135,8.216.17.156,8.216.17.157,8.216.17.161,8.216.17.163,8.216.17.164,8.216.17.181] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 9"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403308; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:371:alert ip [8.216.17.194,8.216.17.216,8.216.17.22,8.216.17.233,8.216.17.243,8.216.17.247,8.216.17.250,8.216.17.50,8.216.17.61,8.216.17.62,8.216.17.84,8.216.17.90,8.216.17.97,8.216.18.107,8.216.2.104,8.216.2.108,8.216.2.109,8.216.2.110,8.216.2.147,8.216.2.17,8.216.2.191,8.216.2.25,8.216.2.27,8.216.2.28,8.216.2.43,8.216.2.69,8.216.2.9,8.216.3.1,8.216.3.102,8.216.3.150,8.216.3.153,8.216.3.165,8.216.3.19,8.216.3.2,8.216.3.201,8.216.3.203,8.216.3.204,8.216.3.212,8.216.3.218,8.216.3.248,8.216.3.28,8.216.3.3,8.216.3.36,8.216.3.37,8.216.3.62,8.216.3.63,8.216.3.84,8.216.3.89,8.216.4.100,8.216.4.104] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 10"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403309; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:372:alert ip [8.216.4.105,8.216.4.113,8.216.4.124,8.216.4.127,8.216.4.13,8.216.4.132,8.216.4.143,8.216.4.147,8.216.4.162,8.216.4.247,8.216.4.250,8.216.4.37,8.216.4.52,8.216.4.67,8.216.4.69,8.216.4.75,8.216.4.78,8.216.4.82,8.216.4.86,8.216.5.102,8.216.5.111,8.216.5.112,8.216.5.117,8.216.5.122,8.216.5.132,8.216.5.135,8.216.5.142,8.216.5.164,8.216.5.175,8.216.5.176,8.216.5.178,8.216.5.181,8.216.5.198,8.216.5.20,8.216.5.202,8.216.5.208,8.216.5.224,8.216.5.233,8.216.5.244,8.216.5.249,8.216.5.30,8.216.5.47,8.216.5.52,8.216.5.64,8.216.5.7,8.216.5.76,8.216.5.82,8.216.5.90,8.216.5.94,8.216.5.99] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 11"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403310; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:373:alert ip [8.216.6.0,8.216.6.103,8.216.6.107,8.216.6.115,8.216.6.132,8.216.6.133,8.216.6.134,8.216.6.146,8.216.6.154,8.216.6.189,8.216.6.191,8.216.6.198,8.216.6.206,8.216.6.219,8.216.6.220,8.216.6.235,8.216.6.24,8.216.6.249,8.216.6.27,8.216.6.44,8.216.6.5,8.216.6.87,8.216.7.115,8.216.7.116,8.216.7.135,8.216.7.14,8.216.7.143,8.216.7.170,8.216.7.173,8.216.7.175,8.216.7.197,8.216.7.200,8.216.7.213,8.216.7.215,8.216.7.218,8.216.7.235,8.216.7.237,8.216.7.238,8.216.7.31,8.216.7.38,8.216.7.42,8.216.7.66,8.216.7.68,8.216.7.69,8.216.7.74,8.216.7.75,8.216.7.76,8.216.8.106,8.216.8.118,8.216.8.127] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 12"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403311; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:374:alert ip [8.216.8.131,8.216.8.134,8.216.8.151,8.216.8.16,8.216.8.160,8.216.8.161,8.216.8.163,8.216.8.168,8.216.8.182,8.216.8.194,8.216.8.196,8.216.8.217,8.216.8.223,8.216.8.228,8.216.8.236,8.216.8.251,8.216.8.253,8.216.8.28,8.216.8.3,8.216.8.30,8.216.8.34,8.216.8.37,8.216.8.45,8.216.8.47,8.216.8.64,8.216.8.78,8.216.8.87,8.216.8.90,8.216.9.107,8.216.9.11,8.216.9.112,8.216.9.116,8.216.9.117,8.216.9.135,8.216.9.157,8.216.9.166,8.216.9.184,8.216.9.202,8.216.9.222,8.216.9.236,8.216.9.246,8.216.9.247,8.216.9.251,8.216.9.30,8.216.9.34,8.216.9.35,8.216.9.48,8.216.9.76,8.216.9.85,8.216.9.90] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 13"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403312; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:375:alert ip [8.217.241.206,8.217.248.249,8.218.26.254,8.219.100.182,8.219.102.103,8.219.109.151,8.219.114.110,8.219.132.68,8.219.173.27,8.219.181.118,8.219.182.127,8.219.190.251,8.219.190.56,8.219.219.158,8.219.222.66,8.219.223.160,8.219.2.243,8.219.232.5,8.219.236.240,8.219.238.77,8.219.239.96,8.219.51.221,8.219.68.3,8.219.76.182,8.219.96.33,8.221.136.6,8.221.139.48,8.222.128.242,8.222.135.53,8.222.154.180,8.222.160.19,8.222.161.183,8.222.181.172,8.222.213.180,8.222.230.46,8.222.242.233,8.222.249.57,8.231.245.206,8.242.169.17,8.242.169.25,8.242.169.27,8.242.185.7,8.243.70.201,8.34.77.136,8.40.170.167,8.43.59.38,9.234.10.190,9.234.151.114,9.234.151.20,9.234.8.125] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 14"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403313; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:376:alert ip [9.234.8.52,9.234.8.67,12.125.34.250,12.125.93.142,12.138.118.250,12.215.172.242,12.68.228.244,12.79.116.210,13.140.137.11,13.140.140.94,13.140.146.177,13.201.63.2,13.203.129.147,13.215.205.160,13.219.1.233,13.64.227.206,13.71.36.156,13.83.162.35,13.86.104.46,13.86.105.19,13.86.106.3,13.86.113.121,13.86.113.214,13.86.115.189,13.86.116.159,13.86.116.162,13.86.116.180,13.86.117.139,13.89.120.212,13.89.124.208,13.89.124.209,13.89.124.211,13.89.124.214,13.89.124.215,13.89.124.217,13.89.124.220,13.89.124.221,13.89.125.18,13.89.125.19,13.89.125.21,13.89.125.224,13.89.125.225,13.89.125.226,13.89.125.227,13.89.125.229,13.89.125.231,13.89.125.24,13.89.125.25,13.89.125.252,13.89.125.253] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 15"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403314; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:377:alert ip [13.89.125.255,13.89.125.26,13.89.125.30,14.103.10.167,14.103.116.74,14.105.27.167,14.107.178.69,14.109.36.219,14.127.25.216,14.127.61.3,14.145.199.47,14.149.229.191,14.152.90.227,14.152.90.228,14.154.175.146,14.157.86.39,14.157.96.255,14.160.107.20,14.163.144.123,14.163.162.238,14.163.27.121,14.165.156.235,14.165.219.0,14.167.100.106,14.169.53.137,14.169.60.103,14.170.8.17,14.173.19.204,14.173.38.191,14.177.167.103,14.178.3.169,14.18.96.22,14.181.60.217,14.182.206.33,14.182.95.140,14.183.237.63,14.183.88.192,14.184.21.140,14.187.1.162,14.187.131.153,14.19.100.69,14.19.214.57,14.192.213.162,14.20.132.44,14.205.104.147,14.205.104.200,14.212.135.34,14.213.20.219,14.216.124.88,14.220.245.37] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 16"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403315; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:378:alert ip [14.221.164.174,14.224.155.210,14.224.184.133,14.224.211.197,14.226.69.46,14.229.227.157,14.229.79.17,14.23.65.194,14.232.166.189,14.233.154.248,14.241.197.159,14.241.229.29,14.241.233.43,14.244.182.72,14.249.115.134,14.249.173.51,14.255.192.134,14.29.215.148,14.29.224.111,14.32.106.73,14.32.242.146,14.38.15.219,14.39.180.249,14.51.128.154,14.52.43.11,14.96.220.46,14.97.4.34,15.204.165.54,15.204.184.105,15.218.140.205,15.235.169.200,15.235.5.241,18.119.209.50,18.179.183.64,18.190.15.50,18.217.208.51,18.221.179.104,20.102.103.195,20.102.105.170,20.102.108.84,20.102.115.137,20.102.116.167,20.102.117.125,20.102.40.205,20.102.42.78,20.102.43.161,20.102.88.108,20.102.89.79,20.102.91.36,20.102.92.213] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 17"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403316; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:379:alert ip [20.102.92.72,20.102.97.100,20.106.168.113,20.106.168.62,20.106.186.120,20.106.186.17,20.106.186.90,20.106.195.185,20.106.195.24,20.106.197.7,20.106.205.254,20.106.206.77,20.106.207.8,20.106.213.99,20.106.231.33,20.106.32.128,20.106.32.153,20.106.33.119,20.106.49.2,20.106.56.125,20.106.56.201,20.106.56.86,20.106.57.131,20.106.57.141,20.106.57.180,20.109.36.225,20.115.45.115,20.115.83.250,20.115.90.12,20.115.90.159,20.115.90.214,20.118.201.169,20.118.202.126,20.118.202.209,20.118.208.65,20.118.213.18,20.118.216.125,20.118.216.147,20.118.217.143,20.118.217.73,20.118.224.96,20.118.225.13,20.118.225.19,20.118.227.20,20.118.232.75,20.118.233.215,20.118.240.71,20.118.241.146,20.118.241.250,20.118.241.35] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 18"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403317; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:380:alert ip [20.118.24.61,20.118.32.171,20.118.32.242,20.118.32.39,20.118.32.47,20.119.103.5,20.119.74.72,20.119.86.53,20.119.86.70,20.119.99.184,20.119.99.194,20.12.240.164,20.12.240.178,20.12.240.184,20.12.240.188,20.12.240.74,20.12.240.9,20.121.139.167,20.121.45.222,20.121.46.221,20.121.46.26,20.121.46.95,20.121.67.158,20.124.80.111,20.124.87.13,20.124.87.15,20.124.93.107,20.125.176.176,20.127.153.188,20.127.155.221,20.127.170.152,20.127.170.172,20.127.170.79,20.127.173.114,20.127.185.20,20.127.187.30,20.127.187.7,20.127.192.218,20.127.200.74,20.127.202.110,20.127.202.128,20.127.202.251,20.127.203.209,20.127.204.214,20.127.208.220,20.127.217.70,20.127.218.58,20.127.220.170,20.127.220.21,20.127.220.33] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 19"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403318; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:381:alert ip [20.127.224.63,20.127.244.253,20.13.123.92,20.14.72.210,20.14.73.1,20.14.73.168,20.14.73.238,20.14.73.54,20.14.73.63,20.14.74.210,20.14.74.80,20.14.75.6,20.14.78.253,20.14.78.26,20.14.79.76,20.14.80.89,20.14.82.143,20.14.87.238,20.14.88.205,20.14.89.71,20.14.90.84,20.14.93.87,20.14.94.72,20.14.95.138,20.150.192.134,20.150.192.39,20.150.192.63,20.150.192.96,20.150.193.141,20.150.193.32,20.150.194.49,20.150.195.172,20.150.196.142,20.15.162.180,20.15.162.204,20.15.162.238,20.15.162.87,20.15.163.139,20.15.163.169,20.15.163.174,20.15.163.245,20.15.164.165,20.15.164.68,20.15.200.100,20.15.200.45,20.15.224.135,20.15.224.64,20.15.225.33,20.15.225.72,20.161.28.97] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 20"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403319; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:382:alert ip [20.161.30.51,20.161.44.181,20.161.60.20,20.163.10.187,20.163.1.211,20.163.13.196,20.163.13.222,20.163.14.102,20.163.14.130,20.163.14.140,20.163.14.19,20.163.14.222,20.163.14.234,20.163.14.238,20.163.14.51,20.163.15.107,20.163.15.119,20.163.15.123,20.163.15.130,20.163.15.131,20.163.15.141,20.163.15.172,20.163.15.174,20.163.15.176,20.163.15.177,20.163.15.178,20.163.15.19,20.163.15.196,20.163.15.20,20.163.15.206,20.163.15.217,20.163.15.218,20.163.15.220,20.163.15.225,20.163.15.238,20.163.15.247,20.163.15.34,20.163.15.91,20.163.16.165,20.163.20.206,20.163.2.150,20.163.2.151,20.163.2.188,20.163.2.42,20.163.2.53,20.163.27.102,20.163.2.80,20.163.30.205,20.163.30.209,20.163.32.211] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 21"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403320; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:383:alert ip [20.163.3.234,20.163.33.218,20.163.33.22,20.163.33.23,20.163.34.41,20.163.34.47,20.163.34.74,20.163.34.94,20.163.3.80,20.163.38.129,20.163.39.86,20.163.5.243,20.163.5.58,20.163.57.193,20.163.58.125,20.163.59.190,20.163.5.98,20.163.60.142,20.163.60.170,20.163.60.199,20.163.60.205,20.163.60.206,20.163.60.228,20.163.6.179,20.163.61.91,20.163.63.192,20.163.74.182,20.163.74.20,20.163.74.93,20.163.76.6,20.163.8.222,20.167.99.230,20.168.0.132,20.168.0.134,20.168.0.135,20.168.0.45,20.168.0.47,20.168.0.72,20.168.0.73,20.168.0.74,20.168.0.84,20.168.0.86,20.168.0.87,20.168.109.236,20.168.1.102,20.168.11.130,20.168.114.245,20.168.118.83,20.168.120.148,20.168.120.151] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 22"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403321; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:384:alert ip [20.168.120.173,20.168.120.210,20.168.120.248,20.168.120.249,20.168.120.250,20.168.120.251,20.168.120.44,20.168.120.8,20.168.121.1,20.168.121.101,20.168.121.140,20.168.121.142,20.168.121.143,20.168.121.152,20.168.121.167,20.168.121.236,20.168.121.239,20.168.121.252,20.168.121.45,20.168.121.46,20.168.12.169,20.168.121.88,20.168.121.92,20.168.121.93,20.168.121.94,20.168.121.95,20.168.122.16,20.168.122.192,20.168.122.3,20.168.122.36,20.168.122.39,20.168.122.53,20.168.122.60,20.168.122.61,20.168.122.81,20.168.122.83,20.168.123.1,20.168.123.121,20.168.123.224,20.168.123.228,20.168.124.0,20.168.124.105,20.168.124.121,20.168.124.128,20.168.124.152,20.168.12.53,20.168.125.90,20.168.125.91,20.168.12.63,20.168.127.104] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 23"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403322; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:385:alert ip [20.168.127.122,20.168.127.123,20.168.127.148,20.168.127.149,20.168.127.154,20.168.127.155,20.168.5.218,20.168.5.220,20.168.5.222,20.168.5.245,20.168.6.14,20.168.6.15,20.168.6.171,20.168.6.22,20.168.6.227,20.168.6.240,20.168.6.241,20.168.6.79,20.168.6.88,20.168.7.10,20.168.7.106,20.168.7.11,20.168.7.129,20.168.7.148,20.168.7.149,20.168.7.21,20.168.7.214,20.168.7.236,20.168.7.237,20.168.7.24,20.168.7.25,20.168.7.42,20.168.7.56,20.168.7.87,20.168.99.52,20.169.104.111,20.169.104.180,20.169.104.204,20.169.104.211,20.169.104.218,20.169.104.239,20.169.104.253,20.169.104.27,20.169.104.65,20.169.105.134,20.169.105.164,20.169.105.181,20.169.105.213,20.169.105.32,20.169.105.48] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 24"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403323; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:386:alert ip [20.169.105.52,20.169.105.81,20.169.105.9,20.169.105.90,20.169.105.96,20.169.106.155,20.169.106.171,20.169.106.201,20.169.106.209,20.169.106.223,20.169.106.26,20.169.106.57,20.169.106.61,20.169.106.62,20.169.106.93,20.169.107.10,20.169.107.109,20.169.107.137,20.169.107.169,20.169.107.188,20.169.107.190,20.169.107.208,20.169.107.210,20.169.107.214,20.169.107.249,20.169.107.26,20.169.107.4,20.169.107.45,20.169.107.54,20.169.107.71,20.169.108.15,20.169.48.134,20.169.48.140,20.169.48.182,20.169.48.59,20.169.49.156,20.169.49.16,20.169.49.231,20.169.49.41,20.169.49.63,20.169.49.86,20.169.50.188,20.169.50.74,20.169.51.3,20.169.53.154,20.169.81.111,20.169.81.90,20.169.83.101,20.169.83.157,20.169.85.177] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 25"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403324; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:387:alert ip [20.169.85.72,20.169.91.55,20.169.91.83,20.171.123.131,20.171.25.13,20.171.25.167,20.171.25.188,20.171.25.42,20.171.26.41,20.171.28.177,20.171.32.24,20.171.32.45,20.171.8.1,20.171.8.149,20.171.8.150,20.171.8.157,20.171.8.181,20.171.8.182,20.171.8.42,20.171.8.62,20.171.8.85,20.171.8.86,20.171.8.87,20.171.9.108,20.171.9.56,20.172.70.211,20.172.70.65,20.172.71.160,20.186.232.151,20.186.232.154,20.193.146.159,20.193.155.251,20.197.12.174,20.204.156.53,20.204.238.158,20.210.107.25,20.212.59.57,20.219.121.219,20.221.56.85,20.221.58.154,20.221.66.142,20.221.68.122,20.221.68.74,20.221.69.50,20.221.72.102,20.221.72.115,20.221.72.174,20.221.72.24,20.221.72.95,20.223.168.112] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 26"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403325; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:388:alert ip [20.228.220.118,20.237.8.12,20.253.48.149,20.29.19.106,20.29.19.243,20.29.21.127,20.29.22.156,20.29.22.204,20.29.23.140,20.29.23.166,20.29.23.70,20.29.23.77,20.29.23.94,20.29.24.16,20.29.24.90,20.29.49.134,20.29.49.244,20.29.49.93,20.29.56.192,20.29.57.104,20.29.57.212,20.29.57.244,20.29.58.2,20.29.8.147,20.38.32.246,20.38.33.240,20.38.35.154,20.38.35.209,20.38.5.218,20.40.208.55,20.40.209.173,20.40.210.26,20.40.216.95,20.40.217.42,20.40.250.17,20.40.250.19,20.40.250.30,20.42.108.100,20.42.92.153,20.42.9.226,20.42.93.58,20.42.95.196,20.46.225.117,20.46.226.34,20.46.226.81,20.46.228.199,20.46.231.114,20.46.235.137,20.46.244.172,20.46.245.69] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 27"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403326; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:389:alert ip [20.46.246.132,20.46.251.132,20.49.61.51,20.51.234.233,20.51.241.104,20.51.245.17,20.51.245.30,20.53.91.31,20.55.15.224,20.55.15.99,20.55.163.179,20.55.2.194,20.55.223.216,20.55.24.39,20.55.29.194,20.55.29.197,20.55.3.202,20.55.3.241,20.55.35.217,20.55.47.113,20.55.4.75,20.55.50.10,20.55.73.223,20.55.84.43,20.55.87.180,20.55.97.129,20.55.98.221,20.62.193.105,20.62.198.61,20.64.104.11,20.64.104.114,20.64.104.120,20.64.104.132,20.64.104.141,20.64.104.154,20.64.104.155,20.64.104.164,20.64.104.177,20.64.104.195,20.64.104.2,20.64.104.229,20.64.104.235,20.64.104.237,20.64.104.27,20.64.104.31,20.64.104.44,20.64.104.62,20.64.104.65,20.64.104.70,20.64.104.82] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 28"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403327; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:390:alert ip [20.64.104.89,20.64.104.92,20.64.104.93,20.64.104.94,20.64.105.112,20.64.105.124,20.64.105.126,20.64.105.127,20.64.105.133,20.64.105.145,20.64.105.146,20.64.105.148,20.64.105.155,20.64.105.156,20.64.105.167,20.64.105.169,20.64.105.174,20.64.105.186,20.64.105.19,20.64.105.192,20.64.105.193,20.64.105.206,20.64.105.221,20.64.105.230,20.64.105.234,20.64.105.236,20.64.105.238,20.64.105.244,20.64.105.248,20.64.105.25,20.64.105.251,20.64.105.32,20.64.105.39,20.64.105.47,20.64.105.53,20.64.105.54,20.64.105.6,20.64.105.77,20.64.105.9,20.64.105.91,20.64.106.116,20.64.106.117,20.64.106.118,20.64.106.155,20.64.106.18,20.64.106.19,20.64.106.28,20.64.106.29,20.64.106.38,20.64.106.41] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 29"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403328; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:391:alert ip [20.64.106.47,20.64.106.58,20.64.106.91,20.64.97.136,20.64.97.78,20.65.136.30,20.65.136.87,20.65.137.167,20.65.137.218,20.65.145.247,20.65.152.136,20.65.152.190,20.65.153.128,20.65.154.130,20.65.154.146,20.65.154.228,20.65.154.237,20.65.168.78,20.65.177.212,20.65.185.115,20.65.185.21,20.65.192.101,20.65.192.160,20.65.192.170,20.65.192.207,20.65.192.214,20.65.192.33,20.65.192.66,20.65.192.67,20.65.192.71,20.65.192.98,20.65.193.0,20.65.193.1,20.65.193.104,20.65.193.105,20.65.193.108,20.65.193.112,20.65.193.113,20.65.193.127,20.65.193.129,20.65.193.136,20.65.193.137,20.65.193.150,20.65.193.152,20.65.193.159,20.65.193.163,20.65.193.189,20.65.193.19,20.65.193.190,20.65.193.191] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 30"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403329; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:392:alert ip [20.65.193.198,20.65.193.199,20.65.193.201,20.65.193.205,20.65.193.207,20.65.193.213,20.65.193.230,20.65.193.234,20.65.193.243,20.65.193.252,20.65.193.255,20.65.193.28,20.65.193.35,20.65.193.66,20.65.193.67,20.65.193.76,20.65.193.78,20.65.193.82,20.65.193.83,20.65.193.94,20.65.194.102,20.65.194.108,20.65.194.111,20.65.194.112,20.65.194.116,20.65.194.119,20.65.194.121,20.65.194.122,20.65.194.123,20.65.194.128,20.65.194.142,20.65.194.143,20.65.194.160,20.65.194.164,20.65.194.167,20.65.194.168,20.65.194.174,20.65.194.176,20.65.194.180,20.65.194.182,20.65.194.183,20.65.194.29,20.65.194.42,20.65.194.43,20.65.194.46,20.65.194.48,20.65.194.57,20.65.194.59,20.65.194.60,20.65.194.61] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 31"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403330; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:393:alert ip [20.65.194.66,20.65.194.68,20.65.194.80,20.65.194.85,20.65.194.87,20.65.194.88,20.65.194.90,20.65.194.96,20.65.194.99,20.65.195.108,20.65.195.112,20.65.195.113,20.65.195.124,20.65.195.17,20.65.195.20,20.65.195.28,20.65.195.30,20.65.195.32,20.65.195.35,20.65.195.37,20.65.195.38,20.65.195.41,20.65.195.44,20.65.195.46,20.65.195.47,20.65.195.48,20.65.195.49,20.65.195.53,20.65.195.57,20.65.195.60,20.65.195.62,20.65.201.12,20.65.202.2,20.65.216.44,20.65.219.131,20.65.219.72,20.65.224.144,20.65.226.8,20.73.126.190,20.73.127.255,20.79.246.133,20.80.104.29,20.80.105.17,20.80.105.50,20.80.105.83,20.80.105.86,20.80.72.204,20.80.80.29,20.80.83.115,20.80.88.134] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 32"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403331; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:394:alert ip [20.80.88.160,20.80.88.197,20.80.88.247,20.80.88.32,20.80.88.7,20.81.183.81,20.81.45.34,20.81.46.136,20.81.46.39,20.81.47.184,20.81.49.255,20.82.185.239,20.83.150.53,20.83.165.140,20.83.167.20,20.83.167.27,20.83.167.28,20.83.167.30,20.83.170.244,20.83.185.81,20.83.27.149,20.83.27.168,20.83.32.182,20.83.40.172,20.83.48.204,20.83.49.34,20.83.49.78,20.84.118.60,20.84.119.5,20.84.144.113,20.84.144.171,20.84.145.61,20.84.152.142,20.84.152.213,20.84.153.170,20.84.153.185,20.84.166.43,20.84.167.44,20.84.41.22,20.84.60.216,20.84.68.210,20.87.198.19,20.98.128.111,20.98.128.122,20.98.128.249,20.98.136.63,20.98.137.43,20.98.164.209,20.98.166.120,20.98.166.209] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 33"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403332; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:395:alert ip [23.101.72.0,23.117.20.173,23.117.226.177,23.120.25.198,23.131.184.104,23.140.244.248,23.147.232.18,23.224.43.18,23.239.4.120,23.239.4.211,23.252.227.150,23.254.204.187,23.92.27.179,23.92.27.206,23.93.76.61,23.94.211.156,23.94.252.189,23.94.44.102,23.94.61.208,23.95.186.183,23.97.62.128,24.120.116.50,24.142.217.110,24.144.116.101,24.144.84.83,24.144.93.224,24.152.30.227,24.199.103.69,24.199.109.75,24.199.115.39,24.199.116.95,24.199.121.244,24.199.126.56,24.222.239.111,24.239.218.130,24.252.101.62,24.31.216.199,24.36.3.189,24.45.250.145,24.47.28.211,24.51.251.135,24.55.199.2,24.67.38.161,24.76.180.68,24.91.100.164,24.95.137.201,27.11.137.204,27.11.185.8,27.123.254.134,27.13.199.63] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 34"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403333; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:396:alert ip [27.147.151.170,27.147.219.58,27.148.196.45,27.152.72.233,27.154.213.174,27.154.3.29,27.158.143.225,27.158.202.29,27.16.194.11,27.17.246.150,27.18.130.85,27.18.186.152,27.18.209.68,27.18.25.128,27.185.17.40,27.185.22.189,27.185.99.133,27.188.24.114,27.188.67.251,27.188.67.72,27.188.69.51,27.19.94.122,27.193.156.197,27.194.229.21,27.199.29.187,27.199.46.234,27.20.122.223,27.203.15.61,27.203.214.184,27.207.2.231,27.211.199.151,27.211.23.252,27.213.115.108,27.215.143.81,27.215.40.127,27.218.154.93,27.222.135.188,27.223.15.94,27.223.31.162,27.224.124.158,27.227.108.206,27.26.14.190,27.26.28.48,27.27.244.183,27.29.116.137,27.3.11.156,27.3.44.202,27.35.65.22,27.37.68.89,27.37.97.112] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 35"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403334; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:397:alert ip [27.4.73.140,27.4.77.215,27.47.25.71,27.50.14.43,27.5.17.44,27.6.100.251,27.6.156.126,27.64.251.114,27.7.196.239,27.7.85.45,27.76.3.56,27.77.243.195,27.84.48.31,27.96.91.92,27.98.232.8,31.10.158.201,31.127.103.158,31.127.117.141,31.132.90.3,31.134.105.211,31.14.254.104,31.14.254.106,31.14.254.112,31.14.254.115,31.14.254.120,31.14.254.124,31.14.254.16,31.14.254.19,31.14.254.22,31.14.254.35,31.14.254.40,31.14.254.46,31.14.254.50,31.14.254.52,31.14.254.6,31.14.254.69,31.14.254.78,31.14.254.88,31.14.254.9,31.14.32.4,31.182.57.86,31.202.90.171,31.208.52.46,31.216.118.69,31.217.160.236,31.220.75.209,31.223.56.188,31.28.111.203,31.37.124.179,31.41.68.66] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 36"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403335; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:398:alert ip [31.43.37.170,31.43.49.155,31.43.59.66,31.56.27.139,31.58.236.100,31.70.86.135,31.97.8.146,31.97.82.54,32.185.130.195,32.218.110.75,32.218.212.195,34.116.141.35,34.116.217.220,34.130.165.0,34.130.170.76,34.13.132.139,34.133.119.173,34.134.183.246,34.134.232.213,34.134.61.111,34.138.7.40,34.140.141.87,34.140.186.72,34.140.78.147,34.14.19.45,34.141.109.4,34.142.56.0,34.142.97.139,34.148.168.102,34.151.118.165,34.156.101.172,34.156.179.179,34.156.196.78,34.156.215.137,34.159.106.16,34.159.223.9,34.166.5.230,34.171.103.2,34.173.87.191,34.177.105.144,34.186.148.151,34.193.119.44,34.197.70.90,34.20.161.165,34.20.228.208,34.228.104.231,34.230.221.101,34.230.56.178,34.32.134.128,34.34.183.65] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 37"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403336; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:399:alert ip [34.39.102.147,34.39.164.118,34.39.176.239,34.39.200.160,34.39.210.88,34.40.80.51,34.46.49.204,34.47.60.176,34.48.147.231,34.50.108.77,34.6.5.60,34.62.143.247,34.62.180.193,34.62.82.148,34.65.105.11,34.65.168.137,34.65.19.13,34.65.64.189,34.68.20.31,34.71.168.205,34.77.197.31,34.77.219.71,34.78.221.236,34.78.28.18,34.79.43.16,34.85.82.146,34.88.148.251,34.88.204.168,34.94.212.149,35.165.112.2,35.169.206.177,35.187.8.142,35.189.102.41,35.198.28.35,35.203.210.10,35.203.210.100,35.203.210.101,35.203.210.102,35.203.210.103,35.203.210.104,35.203.210.105,35.203.210.106,35.203.210.107,35.203.210.108,35.203.210.109,35.203.210.11,35.203.210.110,35.203.210.111,35.203.210.112,35.203.210.114] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 38"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403337; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:400:alert ip [35.203.210.115,35.203.210.116,35.203.210.117,35.203.210.118,35.203.210.119,35.203.210.12,35.203.210.120,35.203.210.121,35.203.210.122,35.203.210.123,35.203.210.124,35.203.210.125,35.203.210.126,35.203.210.128,35.203.210.129,35.203.210.13,35.203.210.130,35.203.210.131,35.203.210.132,35.203.210.133,35.203.210.134,35.203.210.135,35.203.210.136,35.203.210.137,35.203.210.138,35.203.210.139,35.203.210.14,35.203.210.140,35.203.210.141,35.203.210.142,35.203.210.143,35.203.210.144,35.203.210.145,35.203.210.146,35.203.210.147,35.203.210.148,35.203.210.149,35.203.210.15,35.203.210.150,35.203.210.151,35.203.210.153,35.203.210.154,35.203.210.155,35.203.210.156,35.203.210.158,35.203.210.159,35.203.210.160,35.203.210.161,35.203.210.162,35.203.210.163] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 39"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403338; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:401:alert ip [35.203.210.164,35.203.210.165,35.203.210.166,35.203.210.167,35.203.210.168,35.203.210.169,35.203.210.17,35.203.210.170,35.203.210.172,35.203.210.173,35.203.210.174,35.203.210.175,35.203.210.177,35.203.210.179,35.203.210.18,35.203.210.180,35.203.210.181,35.203.210.183,35.203.210.184,35.203.210.185,35.203.210.186,35.203.210.187,35.203.210.188,35.203.210.189,35.203.210.19,35.203.210.190,35.203.210.191,35.203.210.192,35.203.210.194,35.203.210.195,35.203.210.196,35.203.210.197,35.203.210.198,35.203.210.199,35.203.210.20,35.203.210.200,35.203.210.201,35.203.210.202,35.203.210.203,35.203.210.204,35.203.210.205,35.203.210.206,35.203.210.207,35.203.210.209,35.203.210.21,35.203.210.210,35.203.210.211,35.203.210.212,35.203.210.213,35.203.210.214] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 40"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403339; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:402:alert ip [35.203.210.215,35.203.210.216,35.203.210.217,35.203.210.219,35.203.210.22,35.203.210.220,35.203.210.221,35.203.210.222,35.203.210.223,35.203.210.225,35.203.210.226,35.203.210.227,35.203.210.228,35.203.210.229,35.203.210.23,35.203.210.230,35.203.210.231,35.203.210.233,35.203.210.236,35.203.210.237,35.203.210.238,35.203.210.239,35.203.210.243,35.203.210.245,35.203.210.246,35.203.210.247,35.203.210.248,35.203.210.249,35.203.210.25,35.203.210.250,35.203.210.251,35.203.210.252,35.203.210.253,35.203.210.254,35.203.210.26,35.203.210.27,35.203.210.28,35.203.210.3,35.203.210.30,35.203.210.31,35.203.210.32,35.203.210.33,35.203.210.35,35.203.210.38,35.203.210.4,35.203.210.40,35.203.210.41,35.203.210.43,35.203.210.44,35.203.210.45] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 41"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403340; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:403:alert ip [35.203.210.46,35.203.210.47,35.203.210.48,35.203.210.49,35.203.210.5,35.203.210.50,35.203.210.51,35.203.210.52,35.203.210.53,35.203.210.54,35.203.210.55,35.203.210.56,35.203.210.58,35.203.210.59,35.203.210.6,35.203.210.60,35.203.210.61,35.203.210.62,35.203.210.63,35.203.210.64,35.203.210.65,35.203.210.66,35.203.210.67,35.203.210.68,35.203.210.7,35.203.210.70,35.203.210.71,35.203.210.72,35.203.210.73,35.203.210.74,35.203.210.75,35.203.210.76,35.203.210.77,35.203.210.78,35.203.210.79,35.203.210.80,35.203.210.81,35.203.210.82,35.203.210.83,35.203.210.84,35.203.210.85,35.203.210.86,35.203.210.88,35.203.210.89,35.203.210.90,35.203.210.91,35.203.210.92,35.203.210.93,35.203.210.94,35.203.210.95] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 42"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403341; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:404:alert ip [35.203.210.96,35.203.210.97,35.203.210.98,35.203.210.99,35.203.211.10,35.203.211.101,35.203.211.102,35.203.211.103,35.203.211.104,35.203.211.105,35.203.211.106,35.203.211.107,35.203.211.108,35.203.211.109,35.203.211.11,35.203.211.110,35.203.211.111,35.203.211.112,35.203.211.113,35.203.211.115,35.203.211.116,35.203.211.117,35.203.211.118,35.203.211.12,35.203.211.121,35.203.211.123,35.203.211.125,35.203.211.126,35.203.211.127,35.203.211.128,35.203.211.129,35.203.211.13,35.203.211.130,35.203.211.131,35.203.211.132,35.203.211.133,35.203.211.134,35.203.211.135,35.203.211.136,35.203.211.137,35.203.211.14,35.203.211.141,35.203.211.142,35.203.211.145,35.203.211.146,35.203.211.147,35.203.211.149,35.203.211.15,35.203.211.151,35.203.211.152] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 43"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403342; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:405:alert ip [35.203.211.155,35.203.211.157,35.203.211.158,35.203.211.159,35.203.211.16,35.203.211.161,35.203.211.163,35.203.211.164,35.203.211.165,35.203.211.166,35.203.211.167,35.203.211.168,35.203.211.169,35.203.211.17,35.203.211.171,35.203.211.172,35.203.211.173,35.203.211.174,35.203.211.175,35.203.211.176,35.203.211.177,35.203.211.178,35.203.211.18,35.203.211.181,35.203.211.182,35.203.211.183,35.203.211.185,35.203.211.187,35.203.211.188,35.203.211.189,35.203.211.19,35.203.211.190,35.203.211.191,35.203.211.192,35.203.211.193,35.203.211.194,35.203.211.195,35.203.211.196,35.203.211.197,35.203.211.199,35.203.211.20,35.203.211.200,35.203.211.201,35.203.211.202,35.203.211.203,35.203.211.204,35.203.211.205,35.203.211.206,35.203.211.208,35.203.211.209] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 44"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403343; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:406:alert ip [35.203.211.21,35.203.211.210,35.203.211.212,35.203.211.213,35.203.211.215,35.203.211.216,35.203.211.217,35.203.211.218,35.203.211.219,35.203.211.220,35.203.211.221,35.203.211.222,35.203.211.224,35.203.211.225,35.203.211.226,35.203.211.227,35.203.211.228,35.203.211.229,35.203.211.23,35.203.211.230,35.203.211.231,35.203.211.232,35.203.211.233,35.203.211.234,35.203.211.235,35.203.211.236,35.203.211.237,35.203.211.239,35.203.211.24,35.203.211.240,35.203.211.241,35.203.211.243,35.203.211.244,35.203.211.245,35.203.211.246,35.203.211.247,35.203.211.248,35.203.211.249,35.203.211.251,35.203.211.252,35.203.211.253,35.203.211.254,35.203.211.26,35.203.211.27,35.203.211.28,35.203.211.29,35.203.211.3,35.203.211.30,35.203.211.31,35.203.211.33] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 45"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403344; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:407:alert ip [35.203.211.35,35.203.211.37,35.203.211.38,35.203.211.39,35.203.211.4,35.203.211.40,35.203.211.41,35.203.211.42,35.203.211.43,35.203.211.44,35.203.211.45,35.203.211.46,35.203.211.47,35.203.211.48,35.203.211.49,35.203.211.5,35.203.211.50,35.203.211.51,35.203.211.52,35.203.211.53,35.203.211.56,35.203.211.57,35.203.211.58,35.203.211.59,35.203.211.6,35.203.211.60,35.203.211.61,35.203.211.63,35.203.211.64,35.203.211.65,35.203.211.66,35.203.211.67,35.203.211.68,35.203.211.69,35.203.211.7,35.203.211.70,35.203.211.71,35.203.211.72,35.203.211.73,35.203.211.74,35.203.211.75,35.203.211.76,35.203.211.77,35.203.211.78,35.203.211.8,35.203.211.80,35.203.211.82,35.203.211.83,35.203.211.84,35.203.211.86] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 46"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403345; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:408:alert ip [35.203.211.87,35.203.211.88,35.203.211.89,35.203.211.90,35.203.211.91,35.203.211.92,35.203.211.93,35.203.211.95,35.203.211.96,35.203.211.97,35.203.211.98,35.203.211.99,35.204.11.92,35.205.152.237,35.212.204.23,35.216.140.3,35.216.144.195,35.228.207.171,35.228.245.26,35.228.29.83,35.231.55.35,35.240.35.172,35.241.159.1,35.241.65.212,35.245.126.217,35.245.18.112,35.253.86.74,36.105.28.187,36.106.166.119,36.106.166.121,36.106.166.13,36.106.166.16,36.106.166.17,36.106.166.199,36.106.166.206,36.106.166.210,36.106.166.214,36.106.166.217,36.106.166.224,36.106.166.52,36.106.166.79,36.106.166.88,36.106.167.117,36.106.167.12,36.106.167.122,36.106.167.133,36.106.167.26,36.106.167.7,36.106.207.141,36.112.30.31] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 47"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403346; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:409:alert ip [36.129.10.236,36.129.53.173,36.133.16.40,36.133.212.147,36.136.39.46,36.136.39.47,36.136.72.17,36.139.138.72,36.139.84.140,36.140.126.155,36.142.148.181,36.151.146.26,36.153.70.168,36.155.101.97,36.159.131.235,36.161.137.255,36.161.138.106,36.161.236.63,36.22.201.139,36.226.51.140,36.228.218.72,36.234.92.22,36.24.75.125,36.250.158.89,36.251.134.196,36.33.16.145,36.33.216.155,36.38.56.82,36.4.180.114,36.48.255.56,36.50.85.56,36.57.113.227,36.68.118.144,36.7.83.52,36.73.248.109,36.91.191.147,36.92.240.142,36.96.45.10,36.97.177.60,36.99.207.30,37.10.113.211,37.10.113.212,37.10.113.213,37.10.113.215,37.10.113.216,37.10.113.217,37.10.113.218,37.10.113.219,37.10.113.220,37.10.113.221] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 48"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403347; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:410:alert ip [37.120.213.13,37.122.149.83,37.130.153.14,37.130.154.40,37.142.192.99,37.148.210.226,37.148.27.37,37.150.183.226,37.210.227.172,37.228.213.46,37.228.64.54,37.230.79.168,37.239.47.202,37.34.248.33,37.57.113.211,37.60.254.188,37.6.33.9,37.66.146.255,37.66.63.203,37.67.159.204,37.67.84.249,37.72.243.118,37.98.153.179,37.98.217.155,38.137.34.6,38.145.199.204,38.159.224.198,38.188.177.104,38.19.222.154,38.210.105.10,38.210.160.246,38.210.161.18,38.210.181.5,38.210.187.8,38.211.155.130,38.211.234.15,38.224.144.106,38.225.40.59,38.225.40.60,38.226.204.88,38.250.148.98,38.250.181.178,38.253.80.47,38.255.114.125,38.3.133.65,38.3.164.160,38.44.74.172,38.50.85.102,38.52.243.148,38.65.145.249] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 49"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403348; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:411:alert ip [38.65.174.234,38.65.175.47,38.7.18.44,38.7.20.25,38.76.212.178,38.76.229.133,38.76.73.5,38.76.73.6,38.84.209.217,38.96.224.29,39.104.63.170,39.105.202.192,39.105.212.205,39.105.60.119,39.106.212.6,39.107.104.228,39.107.55.186,39.115.137.14,39.129.160.50,39.129.213.135,39.129.41.221,39.129.8.131,39.146.236.42,39.148.238.155,39.152.229.87,39.153.149.150,39.153.183.18,39.153.251.113,39.153.251.117,39.153.252.196,39.154.15.244,39.154.191.14,39.154.7.243,39.156.194.80,39.160.21.55,39.165.116.60,39.165.123.149,39.165.158.43,39.165.57.181,39.165.63.169,39.170.38.142,39.171.193.5,39.171.241.130,39.172.1.204,39.172.236.198,39.172.69.21,39.175.147.214,39.175.52.234,39.181.50.77,39.181.57.125] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 50"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403349; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:412:alert ip [39.182.1.111,39.183.134.81,39.183.136.61,39.184.122.112,39.184.222.126,39.185.31.192,39.187.102.109,39.187.234.199,39.70.28.19,39.72.214.126,39.76.129.19,39.80.190.97,39.96.178.211,39.96.195.130,39.96.203.7,39.96.219.62,39.96.220.52,39.97.54.189,39.99.212.219,40.117.44.94,40.119.26.30,40.119.32.47,40.119.40.156,40.119.41.182,40.119.41.94,40.119.43.103,40.119.46.97,40.122.152.175,40.124.114.161,40.124.116.126,40.124.116.246,40.124.117.126,40.124.120.41,40.124.120.52,40.124.127.239,40.124.168.253,40.124.171.82,40.124.172.100,40.124.172.78,40.124.173.115,40.124.173.139,40.124.173.157,40.124.173.171,40.124.173.185,40.124.173.206,40.124.173.224,40.124.173.251,40.124.173.6,40.124.173.90,40.124.174.133] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 51"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403350; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:413:alert ip [40.124.174.138,40.124.174.148,40.124.174.149,40.124.174.155,40.124.174.187,40.124.174.199,40.124.174.207,40.124.174.209,40.124.174.226,40.124.174.245,40.124.174.248,40.124.174.61,40.124.174.73,40.124.175.103,40.124.175.136,40.124.175.155,40.124.175.16,40.124.175.166,40.124.175.174,40.124.175.188,40.124.175.201,40.124.175.226,40.124.175.233,40.124.175.251,40.124.175.26,40.124.175.30,40.124.175.52,40.124.175.58,40.124.175.60,40.124.175.75,40.124.175.76,40.124.175.86,40.124.178.49,40.124.183.177,40.124.184.7,40.124.185.212,40.124.185.213,40.124.185.240,40.124.186.100,40.124.186.101,40.124.186.155,40.124.186.156,40.124.80.149,40.124.81.157,40.65.186.117,40.67.161.178,40.68.94.149,40.74.212.73,40.75.112.187,40.76.116.105] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 52"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403351; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:414:alert ip [40.76.116.132,40.76.116.33,40.76.117.18,40.76.124.110,40.76.124.195,40.76.124.68,40.76.127.69,40.76.137.103,40.76.139.157,40.76.140.215,40.76.248.253,40.76.250.51,40.80.200.186,40.80.201.49,40.80.203.87,40.80.204.149,40.80.204.175,40.80.206.215,40.82.155.53,40.90.234.147,40.90.249.111,40.90.249.80,40.90.250.163,41.10.220.139,41.110.4.106,41.132.43.27,41.135.218.227,41.135.47.183,41.142.136.181,41.142.182.9,41.157.195.82,41.190.139.82,41.198.159.124,41.209.3.94,41.214.109.39,41.214.32.148,41.216.77.242,41.218.115.194,41.225.157.115,41.242.141.13,41.25.40.194,41.32.217.26,41.33.58.148,41.38.204.111,41.63.235.43,41.63.244.245,41.65.68.75,41.71.81.186,41.72.96.58,41.77.113.79] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 53"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403352; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:415:alert ip [41.77.4.1,41.82.76.214,41.83.225.57,41.83.61.214,41.90.172.7,41.90.177.134,42.1.65.162,42.119.154.94,42.191.217.232,42.193.141.153,42.2.220.46,42.2.4.89,42.228.139.242,42.228.57.186,42.228.58.26,42.232.200.211,42.243.94.40,42.48.12.2,42.5.3.12,42.5.3.14,42.5.3.34,42.5.3.39,42.56.134.238,42.56.171.62,42.60.139.7,42.82.180.58,42.98.221.238,42.98.58.45,43.110.38.5,43.128.122.242,43.134.51.147,43.136.88.51,43.138.243.158,43.139.151.30,43.139.62.181,43.155.183.70,43.156.83.102,43.157.90.232,43.161.232.32,43.166.221.250,43.167.198.92,43.224.126.107,43.225.59.205,43.229.165.52,43.240.157.140,43.242.203.32,43.247.134.15,43.248.108.121,43.248.108.127,43.248.108.129] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 54"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403353; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
/etc/suricata/rules/suricata.rules:416:alert ip [43.248.108.137,43.248.108.139,43.248.108.140,43.248.108.149,43.248.108.150,43.248.108.160,43.248.108.198,43.248.108.214,43.248.108.22,43.248.108.222,43.248.108.228,43.248.108.234,43.248.108.245,43.248.108.253,43.248.108.38,43.248.108.50,43.248.108.57,43.248.108.6,43.248.108.69,43.248.108.7,43.248.108.76,43.248.108.83,43.248.141.14,43.248.185.207,43.254.158.134,43.98.162.186,43.98.164.189,43.98.168.156,43.98.168.235,43.98.169.44,43.98.169.66,43.98.169.68,43.98.170.209,43.98.171.6,43.98.172.148,43.98.174.50,43.98.176.192,43.98.176.193,43.98.178.177,43.98.178.243,43.98.179.14,43.98.180.120,43.98.180.190,43.98.181.206,43.98.183.20,43.98.183.93,43.98.186.15,43.98.188.216,43.98.189.211,43.98.189.5] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 55"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403354; rev:109448; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_06_11;)
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[9] Check Guardian / SG-X custom signatures"
[9] Check Guardian / SG-X custom signatures
root@imx8mp-var-dart:~# grep -RniE 'SGX|Guardian|guardian|Modbus|modbus|sid:10000011|sid:1000' \
>   /etc/suricata/rules /opt/guardian/suricata/rules 2>/dev/null | head -80 || true
/etc/suricata/rules/modbus-events.rules:1:# Modbus Protocol version field is incorrect (Modbus version = 0)
/etc/suricata/rules/modbus-events.rules:2:alert modbus any any -> any any (msg:"SURICATA Modbus invalid Protocol version"; app-layer-event:modbus.invalid_protocol_id; classtype:protocol-command-decode; sid:2250001; rev:2;)
/etc/suricata/rules/modbus-events.rules:4:alert modbus any any -> any any (msg:"SURICATA Modbus unsolicited response"; app-layer-event:modbus.unsolicited_response; classtype:protocol-command-decode; sid:2250002; rev:2;)
/etc/suricata/rules/modbus-events.rules:6:alert modbus any any -> any any (msg:"SURICATA Modbus invalid Length"; app-layer-event:modbus.invalid_length; classtype:protocol-command-decode; sid:2250003; rev:2;)
/etc/suricata/rules/modbus-events.rules:8:alert modbus any any -> any any (msg:"SURICATA Modbus invalid Unit Identifier"; app-layer-event:modbus.invalid_unit_identifier; classtype:protocol-command-decode; sid:2250004; rev:2;)
/etc/suricata/rules/modbus-events.rules:9:# Modbus Function code is incorrect
/etc/suricata/rules/modbus-events.rules:10:alert modbus any any -> any any (msg:"SURICATA Modbus invalid Function code"; app-layer-event:modbus.invalid_function_code; classtype:protocol-command-decode; sid:2250005; rev:2;)
/etc/suricata/rules/modbus-events.rules:11:# Modbus Request/Response value field is incorrect
/etc/suricata/rules/modbus-events.rules:12:alert modbus any any -> any any (msg:"SURICATA Modbus invalid Value"; app-layer-event:modbus.invalid_value; classtype:protocol-command-decode; sid:2250006; rev:2;)
/etc/suricata/rules/modbus-events.rules:13:# Modbus Expception code is incorrect
/etc/suricata/rules/modbus-events.rules:14:alert modbus any any -> any any (msg:"SURICATA Modbus Exception code invalid"; flow:to_client; app-layer-event:modbus.invalid_exception_code; classtype:protocol-command-decode; sid:2250007; rev:2;)
/etc/suricata/rules/modbus-events.rules:15:# Value field in Modbus Response does not match with Modbus Request
/etc/suricata/rules/modbus-events.rules:16:alert modbus any any -> any any (msg:"SURICATA Modbus Data mismatch"; flow:to_client; app-layer-event:modbus.value_mismatch; classtype:protocol-command-decode; sid:2250008; rev:2;)
/etc/suricata/rules/modbus-events.rules:18:alert modbus any any -> any any (msg:"SURICATA Modbus Request flood detected"; flow:to_server; app-layer-event:modbus.flooded; classtype:protocol-command-decode; sid:2250009; rev:2;)
/etc/suricata/rules/suricata.rules:227:# alert modbus any any -> any any (msg:"SURICATA Modbus invalid Protocol version"; app-layer-event:modbus.invalid_protocol_id; classtype:protocol-command-decode; sid:2250001; rev:2;)
/etc/suricata/rules/suricata.rules:228:# alert modbus any any -> any any (msg:"SURICATA Modbus unsolicited response"; app-layer-event:modbus.unsolicited_response; classtype:protocol-command-decode; sid:2250002; rev:2;)
/etc/suricata/rules/suricata.rules:229:# alert modbus any any -> any any (msg:"SURICATA Modbus invalid Length"; app-layer-event:modbus.invalid_length; classtype:protocol-command-decode; sid:2250003; rev:2;)
/etc/suricata/rules/suricata.rules:230:# alert modbus any any -> any any (msg:"SURICATA Modbus invalid Unit Identifier"; app-layer-event:modbus.invalid_unit_identifier; classtype:protocol-command-decode; sid:2250004; rev:2;)
/etc/suricata/rules/suricata.rules:231:# alert modbus any any -> any any (msg:"SURICATA Modbus invalid Function code"; app-layer-event:modbus.invalid_function_code; classtype:protocol-command-decode; sid:2250005; rev:2;)
/etc/suricata/rules/suricata.rules:232:# alert modbus any any -> any any (msg:"SURICATA Modbus invalid Value"; app-layer-event:modbus.invalid_value; classtype:protocol-command-decode; sid:2250006; rev:2;)
/etc/suricata/rules/suricata.rules:233:# alert modbus any any -> any any (msg:"SURICATA Modbus Exception code invalid"; flow:to_client; app-layer-event:modbus.invalid_exception_code; classtype:protocol-command-decode; sid:2250007; rev:2;)
/etc/suricata/rules/suricata.rules:234:# alert modbus any any -> any any (msg:"SURICATA Modbus Data mismatch"; flow:to_client; app-layer-event:modbus.value_mismatch; classtype:protocol-command-decode; sid:2250008; rev:2;)
/etc/suricata/rules/suricata.rules:235:# alert modbus any any -> any any (msg:"SURICATA Modbus Request flood detected"; flow:to_server; app-layer-event:modbus.flooded; classtype:protocol-command-decode; sid:2250009; rev:2;)
/etc/suricata/rules/suricata.rules:27449:alert dns $HOME_NET any -> any any (msg:"ET MALWARE APT28/Sednit DNS Lookup (theguardiannews .org)"; dns.query; content:"theguardiannews.org"; depth:19; nocase; endswith; fast_pattern; reference:url,www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part1.pdf; classtype:targeted-activity; sid:2023384; rev:5; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2016_10_21, deployment Perimeter, malware_family APT28_Sednit, confidence Medium, signature_severity Major, updated_at 2020_09_17;)
/etc/suricata/rules/suricata.rules:30948:alert dns $HOME_NET any -> any any (msg:"ET MALWARE Sidewinder APT Related Domain in DNS Lookup"; dns.query; content:"mailcantonfair.cssc.info"; nocase; bsize:24; reference:url,mp.weixin.qq.com/s/qsGxZIiTsuI7o-_XmiHLHg; classtype:domain-c2; sid:2036653; rev:1; metadata:attack_target Client_Endpoint, created_at 2022_05_23, deployment Perimeter, malware_family Sidewinder, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2022_05_23;)
/etc/suricata/rules/suricata.rules:34125:# alert dns $HOME_NET any -> any any (msg:"ET MALWARE Turla/Crutch CnC Domain in DNS Lookup (theguardian .webredirect .org)"; dns.query; content:"theguardian.webredirect.org"; nocase; bsize:27; reference:url,www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/; classtype:domain-c2; sid:2031255; rev:3; metadata:attack_target Client_Endpoint, created_at 2020_12_03, deployment Perimeter, deprecation_reason Age, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2023_07_27;)
/etc/suricata/rules/suricata.rules:49836:alert dns $HOME_NET any -> any any (msg:"ET MOBILE_MALWARE Android Spy PREDATOR CnC Domain in DNS Lookup"; dns.query; content:"guardian-tt.me"; nocase; bsize:14; reference:url,blog.talosintelligence.com/mercenary-intellexa-predator/; classtype:trojan-activity; sid:2046444; rev:1; metadata:affected_product Android, attack_target Client_Endpoint, created_at 2023_06_21, deployment Perimeter, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2023_06_21, mitre_tactic_id TA0042, mitre_tactic_name Resource_Development, mitre_technique_id T1583, mitre_technique_name Acquire_Infrastructure;)
/etc/suricata/rules/suricata.rules:49953:# alert dns $HOME_NET any -> any any (msg:"ET MOBILE_MALWARE Android Spy PREDATOR CnC Domain in DNS Lookup"; dns.query; bsize:14; content:"guardian-tt.me"; nocase; reference:url,blog.talosintelligence.com/mercenary-intellexa-predator/; classtype:trojan-activity; sid:2046582; rev:2; metadata:affected_product Android, attack_target Mobile_Client, created_at 2023_06_22, deployment Perimeter, deprecation_reason Duplicate, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2023_07_03, mitre_tactic_id TA0042, mitre_tactic_name Resource_Development, mitre_technique_id T1583, mitre_technique_name Acquire_Infrastructure;)
/etc/suricata/rules/suricata.rules:55757:alert tcp any any -> $HOME_NET 27700 (msg:"ET SCADA SEIG Modbus 3.4 - Remote Code Execution"; flow:established,to_server; content:"|42 42 ff ff 07 03 44 00 64|"; fast_pattern; content:"|90 90 90 90 90 90 90 90 90 90|"; distance:0; reference:url,exploit-db.com/exploits/45220/; reference:cve,2013-0662; classtype:attempted-user; sid:2026005; rev:1; metadata:created_at 2018_08_21, cve CVE_2013_0662, confidence High, signature_severity Major, updated_at 2019_07_26, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application;)
/etc/suricata/rules/suricata.rules:56128:# alert tcp any any -> any 502 (msg:"ET SCAN Modbus Scanning detected"; flow:established,to_server; content:"|00 00 00 00 00 02|"; depth:6; threshold: type both, track by_src, count 100, seconds 10; reference:url,code.google.com/p/modscan/; reference:url,www.rtaautomation.com/modbustcp/; classtype:bad-unknown; sid:2009286; rev:4; metadata:created_at 2010_07_30, confidence Medium, signature_severity Informational, updated_at 2020_11_12;)
/etc/suricata/rules/suricata.rules:57188:alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_CLIENT Possible % Encoded Iframe Tag"; flow:established,to_client; content:"%69%66%72%61%6d%65"; nocase; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.guardian.co.uk/technology/2008/apr/03/security.google; classtype:bad-unknown; sid:2012241; rev:2; metadata:affected_product Web_Browsers, affected_product Web_Browser_Plugins, attack_target Client_Endpoint, created_at 2011_01_27, deployment Perimeter, confidence Medium, signature_severity Major, tag Web_Client_Attacks, updated_at 2019_07_26;)
/etc/suricata/rules/suricata.rules:57189:alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_CLIENT Possible %u UTF-8 Encoded Iframe Tag"; flow:established,to_client; content:"%u69%u66%u72%u61%u6d%u65"; nocase; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.guardian.co.uk/technology/2008/apr/03/security.google; classtype:bad-unknown; sid:2012242; rev:2; metadata:affected_product Web_Browsers, affected_product Web_Browser_Plugins, attack_target Client_Endpoint, created_at 2011_01_27, deployment Perimeter, confidence Medium, signature_severity Major, tag Web_Client_Attacks, updated_at 2019_07_26;)
/etc/suricata/rules/suricata.rules:57190:alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_CLIENT Possible %u UTF-16 Encoded Iframe Tag"; flow:established,to_client; content:"%u6966%u7261%u6d65"; nocase; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.guardian.co.uk/technology/2008/apr/03/security.google; classtype:bad-unknown; sid:2012243; rev:2; metadata:affected_product Web_Browsers, affected_product Web_Browser_Plugins, attack_target Client_Endpoint, created_at 2011_01_27, deployment Perimeter, confidence Medium, signature_severity Major, tag Web_Client_Attacks, updated_at 2019_07_26;)
/etc/suricata/rules/suricata.rules:57191:alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_CLIENT Possible # Encoded Iframe Tag"; flow:established,to_client; content:"#69#66#72#61#6d#65"; nocase; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.guardian.co.uk/technology/2008/apr/03/security.google; classtype:bad-unknown; sid:2012244; rev:2; metadata:affected_product Web_Browsers, affected_product Web_Browser_Plugins, attack_target Client_Endpoint, created_at 2011_01_27, deployment Perimeter, confidence Medium, signature_severity Major, tag Web_Client_Attacks, updated_at 2019_07_26;)
/etc/suricata/rules/local.rules:1:alert icmp any any -> any any (msg:"SGX SURICATA IDS ENGINE TEST"; sid:10000011; rev:1;)
/etc/suricata/rules/local.rules:2:alert icmp any any -> any any (msg:"SGX INLINE BLOCK TEST HIGH"; priority:1; sid:10000099; rev:1;)
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[10] Final Suricata config + rules load test"
[10] Final Suricata config + rules load test
root@imx8mp-var-dart:~# suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -80
18/6/2026 -- 09:26:21 - <Info> - Running suricata under test mode
18/6/2026 -- 09:26:21 - <Notice> - This is Suricata version 6.0.4 RELEASE running in SYSTEM mode
18/6/2026 -- 09:26:21 - <Info> - CPUs/cores online: 4
18/6/2026 -- 09:26:21 - <Info> - fast output device (regular) initialized: fast.log
18/6/2026 -- 09:26:21 - <Info> - eve-log output device (regular) initialized: eve.json
18/6/2026 -- 09:26:21 - <Info> - stats output device (regular) initialized: stats.log
18/6/2026 -- 09:26:32 - <Info> - 2 rule files processed. 50644 rules successfully loaded, 0 rules failed
18/6/2026 -- 09:26:32 - <Info> - Threshold config parsed: 0 rule(s) found
18/6/2026 -- 09:26:40 - <Info> - 50649 signatures processed. 1292 are IP-only rules, 5238 are inspecting packet payload, 43901 inspect application layer, 108 are decoder event only
18/6/2026 -- 09:31:06 - <Notice> - Configuration provided was successfully loaded. Exiting.
18/6/2026 -- 09:31:07 - <Info> - cleaning up signature grouping structure... complete
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "======================================"
======================================
root@imx8mp-var-dart:~# echo "VERIFY COMPLETE"
VERIFY COMPLETE
root@imx8mp-var-dart:~# echo "======================================"^C
root@imx8mp-var-dart:~# # Step 1: Current pid check
root@imx8mp-var-dart:~# cat /var/run/suricata.pid
751085
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Step 2: Full Suricata restart
root@imx8mp-var-dart:~# kill $(cat /var/run/suricata.pid)
-sh: kill: (751085) - No such process
root@imx8mp-var-dart:~# sleep 3
root@imx8mp-var-dart:~# suricata -c /etc/suricata/suricata.yaml -i wlan0 -D
18/6/2026 -- 09:33:48 - <Notice> - This is Suricata version 6.0.4 RELEASE running in SYSTEM mode
18/6/2026 -- 09:33:48 - <Error> - [ERRCODE: SC_ERR_INITIALIZATION(45)] - pid file '/var/run/suricata.pid' exists but appears stale. Make sure Suricata is not running and then remove /var/run/suricata.pid. Aborting!
root@imx8mp-var-dart:~# sleep 10
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Step 3: Verify new rule loaded
root@imx8mp-var-dart:~# grep "10000099" /var/log/suricata/suricata.log | tail -3
root@imx8mp-var-dart:~# suricata-update list-enabled-sources 2>/dev/null || grep "local.rules" /etc/suricata/suricata.yaml
  - local.rules
root@imx8mp-var-dart:~# echo "=== FINAL SERVICE CONFIRM ==="
=== FINAL SERVICE CONFIRM ===
root@imx8mp-var-dart:~# systemctl is-enabled suricata
enabled
root@imx8mp-var-dart:~# systemctl is-active suricata
active
root@imx8mp-var-dart:~# systemctl status suricata --no-pager -l
● suricata.service - Suricata IDS/IPS Engine for SG-X Guardian
     Loaded: loaded (/etc/systemd/system/suricata.service; enabled; preset: disabled)
     Active: active (running) since Thu 2026-06-18 09:50:50 UTC; 3min 7s ago
       Docs: man:suricata(1)
    Process: 813624 ExecStartPre=/bin/sh -c rm -f /var/run/suricata.pid /run/suricata.pid (code=exited, status=0/SUCCESS)
   Main PID: 813625 (Suricata-Main)
      Tasks: 1 (limit: 3167)
     Memory: 572.1M
     CGroup: /system.slice/suricata.service
             └─813625 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0

Jun 18 09:50:50 imx8mp-var-dart systemd[1]: Starting Suricata IDS/IPS Engine for SG-X Guardian...
Jun 18 09:50:50 imx8mp-var-dart systemd[1]: Started Suricata IDS/IPS Engine for SG-X Guardian.
Jun 18 09:50:50 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:50:50 - <Notice> - This is Suricata version 6.0.4 RELEASE running in SYSTEM mode
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "=== SURICATA PROCESS ==="
=== SURICATA PROCESS ===
root@imx8mp-var-dart:~# ps aux | grep '[s]uricata'
root      813625 99.2 16.0 605160 593092 ?       Rs   09:50   3:06 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "=== STARTUP LOG CHECK ==="
=== STARTUP LOG CHECK ===
root@imx8mp-var-dart:~# tail -n 100 /var/log/suricata/suricata.log | grep -Ei "rules successfully loaded|rules failed|engine started|All AFP|Error|failed" || true
18/6/2026 -- 07:04:58 - <Error> - [ERRCODE: SC_ERR_INITIALIZATION(45)] - pid file '/var/run/suricata.pid' exists but appears stale. Make sure Suricata is not running and then remove /var/run/suricata.pid. Aborting!
18/6/2026 -- 07:12:04 - <Info> - 2 rule files processed. 50643 rules successfully loaded, 0 rules failed
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 07:16:01 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 07:16:01 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
18/6/2026 -- 07:16:01 - <Info> - All AFP capture threads are running.
18/6/2026 -- 07:39:14 - <Error> - [ERRCODE: SC_ERR_INITIALIZATION(45)] - pid file '/var/run/suricata.pid' exists and Suricata appears to be running. Aborting!
18/6/2026 -- 09:21:58 - <Info> - 2 rule files processed. 50644 rules successfully loaded, 0 rules failed
18/6/2026 -- 09:26:32 - <Info> - 2 rule files processed. 50644 rules successfully loaded, 0 rules failed
18/6/2026 -- 09:33:48 - <Error> - [ERRCODE: SC_ERR_INITIALIZATION(45)] - pid file '/var/run/suricata.pid' exists but appears stale. Make sure Suricata is not running and then remove /var/run/suricata.pid. Aborting!
18/6/2026 -- 09:39:36 - <Info> - 2 rule files processed. 50644 rules successfully loaded, 0 rules failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
18/6/2026 -- 09:43:35 - <Info> - All AFP capture threads are running.
18/6/2026 -- 09:50:57 - <Info> - 2 rule files processed. 50644 rules successfully loaded, 0 rules failed
root@imx8mp-var-dart:~# echo "======================================"
_IFACE=$(ip route | awk '/default/ {print $5; exit}')
ROUTE_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

echo "DEFAULT_IFACE=$DEFAULT_IFACE"
echo "ROUTE_IFACE=$ROUTE_IFACE"
ip -br addr ======================================
|| true

echo
echo "[2] Suricata service status"
systemctl is-enabled suricata || true
systemctl is-active suricata || true
systemctl status suricata --no-pager -l || true

echo
echo "[3] Suricata running process/interface"
ps aux | grep '[s]uricata' || true

echo
echo "[4] Suricata service ExecStart command"
systemctl cat suricata || true

echo
echo "[5] suricata.yaml AF_PACKET interface config"
grep -n "af-packet" -A35 /etc/suricata/suricata.yaml || true

echo
echo "[6] BEFORE packet counters"
tail -n 500 /var/log/suricata/stats.lroot@imx8mp-var-dart:~# echo "VERIFY: PACKET CAPTURE INTEGRATION"
VERIFY: PACKET CAPTURE INTEGRATION
root@imx8mp-var-dart:~# echo "======================================"
======================================
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[1] Guardian active/default interface"
[1] Guardian active/default interface
root@imx8mp-var-dart:~# DEFAULT_IFACE=$(ip route | awk '/default/ {print $5; exit}')
og 2>/dev/null | grep -E "capture.kernel_packets|capture.kernel_drops|decoder.pkts|decoder.invalid" | tail -30 || true

echo
echo "[7] Generate controlled real network traffic"
ping -c 5 8.8.8.8 || true
curl -I http://example.com --max-time 10 || true
sleep 10

echo
echo "[8] AFTER packet counters"
tail -n 500 /var/log/suricata/stats.log 2>/dev/null | grep -E "capture.kernel_packets|capture.kernel_drops|decoder.pkts|decoder.invalid" | tail -40 || true

echo
echo "[9] Drop/errroot@imx8mp-var-dart:~# ROUTE_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i+1); exit}}')t $(i
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "DEFAULT_IFACE=$DEFAULT_IFACE"
DEFAULT_IFACE=wlan0
root@imx8mp-var-dart:~# echo "ROUTE_IFACE=$ROUTE_IFACE"
ROUTE_IFACE=wlan0
root@imx8mp-var-dart:~# ip -br addr || true
lo               UNKNOWN        127.0.0.1/8 ::1/128
defined1         UNKNOWN        10.100.0.33/16 fe80::c5e6:9099:7aa7:5bcb/64
wlan1            DOWN
uap1             DOWN
wfd1             DOWN
wlan0            UP             192.168.50.103/24 fe80::1d0d:9237:b17c:aafd/64
uap0             DOWN           192.168.200.1/24
wfd0             DOWN
wwan0            UNKNOWN
eth0             DOWN
nebula0          UNKNOWN        192.168.100.1/24 fe80::7d30:e8ac:29cc:d390/64
or check"
tail -n 500 /var/log/suricata/stats.log 2>/dev/null | grep -Ei "capture.kernel_drops|decoder.invalid|drop|error|failed" | tail -80 || true

echo
echo "[10] Service stability check"
systemctl is-active suricata || true
ps aux | grep '[s]uricata' || true
journalctl -u suricata --since "10 minutes ago" --no-pager | grep -Ei "started|engine started|All AFP|error|failed|panic|crash|aborting" || true

echo "======================================"
echo "PACKET CAPTURE VERIroot@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[2] Suricata service status"
[2] Suricata service status
root@imx8mp-var-dart:~# systemctl is-enabled suricata || true
FY COMPLETE"
echo "======================================"enabled
root@imx8mp-var-dart:~# systemctl is-active suricata || true
active
root@imx8mp-var-dart:~# systemctl status suricata --no-pager -l || true
● suricata.service - Suricata IDS/IPS Engine for SG-X Guardian
     Loaded: loaded (/etc/systemd/system/suricata.service; enabled; preset: disabled)
     Active: active (running) since Thu 2026-06-18 09:50:50 UTC; 15min ago
       Docs: man:suricata(1)
    Process: 813624 ExecStartPre=/bin/sh -c rm -f /var/run/suricata.pid /run/suricata.pid (code=exited, status=0/SUCCESS)
   Main PID: 813625 (Suricata-Main)
      Tasks: 10 (limit: 3167)
     Memory: 1.0G
     CGroup: /system.slice/suricata.service
             └─813625 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0

Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[3] Suricata running process/interface"
[3] Suricata running process/interface
root@imx8mp-var-dart:~# ps aux | grep '[s]uricata' || true
root      813625 30.1 30.8 1725252 1137224 ?     Ssl  09:50   4:34 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[4] Suricata service ExecStart command"
[4] Suricata service ExecStart command
root@imx8mp-var-dart:~# systemctl cat suricata || true
# /etc/systemd/system/suricata.service
[Unit]
Description=Suricata IDS/IPS Engine for SG-X Guardian
Documentation=man:suricata(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/bin/sh -c 'rm -f /var/run/suricata.pid /run/suricata.pid'
ExecStart=/opt/suricata/bin/suricata -c /etc/suricata/suricata.yaml -i wlan0
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[5] suricata.yaml AF_PACKET interface config"
[5] suricata.yaml AF_PACKET interface config
root@imx8mp-var-dart:~# grep -n "af-packet" -A35 /etc/suricata/suricata.yaml || true
580:af-packet:
581-  - interface: wlan0
582-    # Number of receive threads. "auto" uses the number of cores
583-    #threads: auto
584-    # Default clusterid. AF_PACKET will load balance packets based on flow.
585-    cluster-id: 99
586-    # Default AF_PACKET cluster type. AF_PACKET can load balance per flow or per hash.
587-    # This is only supported for Linux kernel > 3.1
588-    # possible value are:
589-    #  * cluster_flow: all packets of a given flow are sent to the same socket
590-    #  * cluster_cpu: all packets treated in kernel by a CPU are sent to the same socket
591-    #  * cluster_qm: all packets linked by network card to a RSS queue are sent to the same
592-    #  socket. Requires at least Linux 3.14.
593-    #  * cluster_ebpf: eBPF file load balancing. See doc/userguide/capture-hardware/ebpf-xdp.rst for
594-    #  more info.
595-    # Recommended modes are cluster_flow on most boxes and cluster_cpu or cluster_qm on system
596-    # with capture card using RSS (requires cpu affinity tuning and system IRQ tuning)
597-    cluster-type: cluster_flow
598-    # In some fragmentation cases, the hash can not be computed. If "defrag" is set
599-    # to yes, the kernel will do the needed defragmentation before sending the packets.
600-    defrag: yes
601-    # To use the ring feature of AF_PACKET, set 'use-mmap' to yes
602-    #use-mmap: yes
603-    # Lock memory map to avoid it being swapped. Be careful that over
604-    # subscribing could lock your system
605-    #mmap-locked: yes
606-    # Use tpacket_v3 capture mode, only active if use-mmap is true
607-    # Don't use it in IPS or TAP mode as it causes severe latency
608-    #tpacket-v3: yes
609-    # Ring size will be computed with respect to "max-pending-packets" and number
610-    # of threads. You can set manually the ring size in number of packets by setting
611-    # the following value. If you are using flow "cluster-type" and have really network
612-    # intensive single-flow you may want to set the "ring-size" independently of the number
613-    # of threads:
614-    #ring-size: 2048
615-    # Block size is used by tpacket_v3 only. It should set to a value high enough to contain
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[6] BEFORE packet counters"
[6] BEFORE packet counters
root@imx8mp-var-dart:~# tail -n 500 /var/log/suricata/stats.log 2>/dev/null | grep -E "capture.kernel_packets|capture.kernel_drops|decoder.pkts|decoder.invalid" | tail -30 || true
capture.kernel_packets                        | Total                     | 18780
decoder.pkts                                  | Total                     | 18786
capture.kernel_packets                        | Total                     | 18952
decoder.pkts                                  | Total                     | 18952
capture.kernel_packets                        | Total                     | 19284
decoder.pkts                                  | Total                     | 19284
capture.kernel_packets                        | Total                     | 19412
decoder.pkts                                  | Total                     | 19412
capture.kernel_packets                        | Total                     | 19688
decoder.pkts                                  | Total                     | 19693
capture.kernel_packets                        | Total                     | 19976
decoder.pkts                                  | Total                     | 19981
capture.kernel_packets                        | Total                     | 20249
decoder.pkts                                  | Total                     | 20249
capture.kernel_packets                        | Total                     | 20459
decoder.pkts                                  | Total                     | 20460
capture.kernel_packets                        | Total                     | 20679
decoder.pkts                                  | Total                     | 20680
capture.kernel_packets                        | Total                     | 20827
decoder.pkts                                  | Total                     | 20828
capture.kernel_packets                        | Total                     | 21196
decoder.pkts                                  | Total                     | 21205
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[7] Generate controlled real network traffic"
[7] Generate controlled real network traffic
root@imx8mp-var-dart:~# ping -c 5 8.8.8.8 || true
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=54.8 ms

--- 8.8.8.8 ping statistics ---
5 packets transmitted, 1 received, 80% packet loss, time 4075ms
rtt min/avg/max/mdev = 54.800/54.800/54.800/0.000 ms
root@imx8mp-var-dart:~# curl -I http://example.com --max-time 10 || true
HTTP/1.1 200 OK
Date: Thu, 18 Jun 2026 10:06:06 GMT
Content-Type: text/html
Connection: keep-alive
Server: cloudflare
Last-Modified: Tue, 16 Jun 2026 20:39:21 GMT
Allow: GET, HEAD
Accept-Ranges: bytes
Age: 12886
cf-cache-status: HIT
CF-RAY: a0d97ab7b88fde99-EWR

root@imx8mp-var-dart:~# sleep 10
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[8] AFTER packet counters"
[8] AFTER packet counters
root@imx8mp-var-dart:~# tail -n 500 /var/log/suricata/stats.log 2>/dev/null | grep -E "capture.kernel_packets|capture.kernel_drops|decoder.pkts|decoder.invalid" | tail -40 || true
capture.kernel_packets                        | Total                     | 19284
decoder.pkts                                  | Total                     | 19284
capture.kernel_packets                        | Total                     | 19412
decoder.pkts                                  | Total                     | 19412
capture.kernel_packets                        | Total                     | 19688
decoder.pkts                                  | Total                     | 19693
capture.kernel_packets                        | Total                     | 19976
decoder.pkts                                  | Total                     | 19981
capture.kernel_packets                        | Total                     | 20249
decoder.pkts                                  | Total                     | 20249
capture.kernel_packets                        | Total                     | 20459
decoder.pkts                                  | Total                     | 20460
capture.kernel_packets                        | Total                     | 20679
decoder.pkts                                  | Total                     | 20680
capture.kernel_packets                        | Total                     | 20827
decoder.pkts                                  | Total                     | 20828
capture.kernel_packets                        | Total                     | 21196
decoder.pkts                                  | Total                     | 21205
capture.kernel_packets                        | Total                     | 21639
decoder.pkts                                  | Total                     | 21643
capture.kernel_packets                        | Total                     | 21833
decoder.pkts                                  | Total                     | 21834
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[9] Drop/error check"
[9] Drop/error check
root@imx8mp-var-dart:~# tail -n 500 /var/log/suricata/stats.log 2>/dev/null | grep -Ei "capture.kernel_drops|decoder.invalid|drop|error|failed" | tail -80 || true
app_layer.flow.failed_tcp                     | Total                     | 334
app_layer.flow.failed_udp                     | Total                     | 358
app_layer.flow.failed_tcp                     | Total                     | 337
app_layer.flow.failed_udp                     | Total                     | 359
app_layer.flow.failed_tcp                     | Total                     | 344
app_layer.flow.failed_udp                     | Total                     | 363
app_layer.flow.failed_tcp                     | Total                     | 347
app_layer.flow.failed_udp                     | Total                     | 372
app_layer.flow.failed_tcp                     | Total                     | 350
app_layer.flow.failed_udp                     | Total                     | 377
app_layer.flow.failed_tcp                     | Total                     | 357
app_layer.flow.failed_udp                     | Total                     | 380
app_layer.flow.failed_tcp                     | Total                     | 360
app_layer.flow.failed_udp                     | Total                     | 385
app_layer.flow.failed_tcp                     | Total                     | 364
app_layer.flow.failed_udp                     | Total                     | 389
app_layer.flow.failed_tcp                     | Total                     | 370
app_layer.flow.failed_udp                     | Total                     | 395
app_layer.flow.failed_tcp                     | Total                     | 374
app_layer.flow.failed_udp                     | Total                     | 397
app_layer.flow.failed_tcp                     | Total                     | 380
app_layer.flow.failed_udp                     | Total                     | 403
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[10] Service stability check"
[10] Service stability check
root@imx8mp-var-dart:~# systemctl is-active suricata || true
active
root@imx8mp-var-dart:~# ps aux | grep '[s]uricata' || true
root      813625 29.7 30.8 1725252 1137224 ?     Ssl  09:50   4:35 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0
root@imx8mp-var-dart:~# journalctl -u suricata --since "10 minutes ago" --no-pager | grep -Ei "started|engine started|All AFP|error|failed|panic|crash|aborting" || true
root@imx8mp-var-dart:~# echo "======================================"
Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\Stores> ssh root@192.168.50.103
Last login: Thu Jun 18 04:09:21 2026 from 192.168.50.108
root@imx8mp-var-dart:~# me ye use kr leta ap wo first wala use krn lena ok?^C
root@imx8mp-var-dart:~# # Stale pid file remove karo
root@imx8mp-var-dart:~# rm /var/run/suricata.pid
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Fresh start
root@imx8mp-var-dart:~# suricata -c /etc/suricata/suricata.yaml -i wlan0 -D
18/6/2026 -- 09:39:29 - <Notice> - This is Suricata version 6.0.4 RELEASE running in SYSTEM mode
root@imx8mp-var-dart:~# sleep 15
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Rule loaded verify karo
root@imx8mp-var-dart:~# grep "10000099\|local.rules\|Loading rule" /var/log/suricata/suricata.log | tail -5
root@imx8mp-var-dart:~# pgrep -af [Ss]uricata
809021 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0 -D
root@imx8mp-var-dart:~# # Alert trigger karo
root@imx8mp-var-dart:~# ping -c 5 192.168.50.1 > /dev/null
| tail -1 | python3 -m json.tool | head -15
root@imx8mp-var-dart:~# sleep 5
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # New rule fire hua ya nahi
root@imx8mp-var-dart:~# grep "INLINE BLOCK TEST\|10000099" /var/log/suricata/fast.log | tail -5
root@imx8mp-var-dart:~# grep "10000099" /var/log/suricata/eve.json | tail -1 | python3 -m json.tool | head -15
Expecting value: line 1 column 1 (char 0)
root@imx8mp-var-dart:~# grep -A5 "rule-files" /etc/suricata/suricata.yaml | head -15
rule-files:
  - local.rules
  - suricata.rules

##
## Auxiliary configuration files.
root@imx8mp-var-dart:~# tail -3 /etc/suricata/rules/local.rules
alert icmp any any -> any any (msg:"SGX SURICATA IDS ENGINE TEST"; sid:10000011; rev:1;)
alert icmp any any -> any any (msg:"SGX INLINE BLOCK TEST HIGH"; priority:1; sid:10000099; rev:1;)
root@imx8mp-var-dart:~# grep -n "local.rules\|rule-files\|default-rule-path" /etc/suricata/suricata.yaml | head -15
1872:default-rule-path: /etc/suricata/rules
1874:rule-files:
1875:  - local.rules
root@imx8mp-var-dart:~# echo "=== STOP MANUAL SURICATA IF RUNNING ==="
=== STOP MANUAL SURICATA IF RUNNING ===
root@imx8mp-var-dart:~# pkill -f "/opt/suricata/bin/suricata.real" || true
"=== CLEAN STALE PID ==="
rm -f /var/run/suricata.pid
rm -f /run/suricata.pid

echo "=== CREATE SYSTEMD SERVICE ==="
cat > /etc/systemd/system/suricata.service <<'EOF'
[Unit]
Description=Suricata IDS/IPS Engine for SG-X Guardian
Documentation=man:suricata(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/bin/sh -c 'rm -f /var/run/suricata.pid /run/suricata.pid'
ExecStart=/opt/suricata/bin/suricata -c /etc/suricata/suricata.yaml -i wlan0
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

echo "=== ENABLE AND START SERVICE ==="
systemctl daemon-reload
systemctl enable suricata
systemctl start suricata

echo "=== VERIFY SERVICE ==="
systemctl status suricata --no-pager
ps aux | grep '[s]uricata'root@imx8mp-var-dart:~# sleep 2
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "=== CLEAN STALE PID ==="
=== CLEAN STALE PID ===
root@imx8mp-var-dart:~# rm -f /var/run/suricata.pid
root@imx8mp-var-dart:~# rm -f /run/suricata.pid
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "=== CREATE SYSTEMD SERVICE ==="
=== CREATE SYSTEMD SERVICE ===
root@imx8mp-var-dart:~# cat > /etc/systemd/system/suricata.service <<'EOF'
> [Unit]
> Description=Suricata IDS/IPS Engine for SG-X Guardian
> Documentation=man:suricata(1)
> After=network-online.target
> Wants=network-online.target
>
> [Service]
> Type=simple
> User=root
> Group=root
> ExecStartPre=/bin/sh -c 'rm -f /var/run/suricata.pid /run/suricata.pid'
> ExecStart=/opt/suricata/bin/suricata -c /etc/suricata/suricata.yaml -i wlan0
> ExecStop=/bin/kill -TERM $MAINPID
> Restart=on-failure
> RestartSec=5
> LimitNOFILE=65535
>
> [Install]
> WantedBy=multi-user.target
> EOF
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "=== ENABLE AND START SERVICE ==="
=== ENABLE AND START SERVICE ===
root@imx8mp-var-dart:~# systemctl daemon-reload
root@imx8mp-var-dart:~# systemctl enable suricata
Created symlink /etc/systemd/system/multi-user.target.wants/suricata.service → /etc/systemd/system/suricata.service.
root@imx8mp-var-dart:~# systemctl start suricata
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "=== VERIFY SERVICE ==="
=== VERIFY SERVICE ===
root@imx8mp-var-dart:~# systemctl status suricata --no-pager
● suricata.service - Suricata IDS/IPS Engine for SG-X Guardian
     Loaded: loaded (/etc/systemd/system/suricata.service; enabled; preset: disabled)
     Active: active (running) since Thu 2026-06-18 09:50:50 UTC; 41ms ago
       Docs: man:suricata(1)
    Process: 813624 ExecStartPre=/bin/sh -c rm -f /var/run/suricata.pid /run/suricata.pid (code=exited, status=0/SUCCESS)
   Main PID: 813625 (Suricata-Main)
      Tasks: 1 (limit: 3167)
     Memory: 1.1M
     CGroup: /system.slice/suricata.service
             └─813625 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/surica…

Jun 18 09:50:50 imx8mp-var-dart systemd[1]: Starting Suricata IDS/IPS Engine for SG-X Guardian...
Jun 18 09:50:50 imx8mp-var-dart systemd[1]: Started Suricata IDS/IPS Engine for SG-X Guardian.
Jun 18 09:50:50 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:50:50 - <Notice> - This is Suricata version 6.…EM mode
Hint: Some lines were ellipsized, use -l to show in full.
root@imx8mp-var-dart:~# ps aux | grep '[s]uricata'
root      813625 99.5  7.3 281756 269784 ?       Rs   09:50   0:04 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0
root@imx8mp-var-dart:~# # fast.log mein latest entries check karo (restart ke baad)
root@imx8mp-var-dart:~# tail -10 /var/log/suricata/fast.log
06/18/2026-09:49:19.340051  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.115:42264 -> 192.168.50.103:50062
06/18/2026-09:49:32.242760  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.115:56824 -> 192.168.50.103:50062
06/18/2026-09:49:40.639183  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.248:56292 -> 192.168.50.103:50062
06/18/2026-09:49:44.530426  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.115:56078 -> 192.168.50.103:50062
06/18/2026-09:50:17.196191  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.248:57458 -> 192.168.50.103:50062
06/18/2026-09:50:17.810391  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.248:57474 -> 192.168.50.103:50062
06/18/2026-09:50:20.491325  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.115:58830 -> 192.168.50.103:50062
06/18/2026-09:50:20.499733  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.115:58832 -> 192.168.50.103:50062
06/18/2026-09:50:32.556268  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.115:47728 -> 192.168.50.103:50062
06/18/2026-09:50:33.068889  [**] [1:2210044:2] SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.50.115:47740 -> 192.168.50.103:50062
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Eve.json mein latest alert check karo
root@imx8mp-var-dart:~# grep '"event_type":"alert"' /var/log/suricata/eve.json | tail -3 | python3 -m json.tool 2>/dev/null | grep "signature\|timestamp"
root@imx8mp-var-dart:~# echo "=== CURRENT SERVICE FINAL CHECK ==="
=== CURRENT SERVICE FINAL CHECK ===
nE "SGX|10000011|10000099" /etc/suricata/rules/local.rules

echo "--- latest startup logs since service start ---"
journalctl -u suricata --since "2026-06-18 09:50:50" --no-pager

echo "--- laroot@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "--- enabled/active ---"
--- enabled/active ---
root@imx8mp-var-dart:~# systemctl is-enabled suricata
enabled
root@imx8mp-var-dart:~# systemctl is-active suricata
active
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "--- status ---"
--- status ---
root@imx8mp-var-dart:~# systemctl status suricata --no-pager -l
● suricata.service - Suricata IDS/IPS Engine for SG-X Guardian
     Loaded: loaded (/etc/systemd/system/suricata.service; enabled; preset: disabled)
     Active: active (running) since Thu 2026-06-18 09:50:50 UTC; 5min ago
       Docs: man:suricata(1)
    Process: 813624 ExecStartPre=/bin/sh -c rm -f /var/run/suricata.pid /run/suricata.pid (code=exited, status=0/SUCCESS)
   Main PID: 813625 (Suricata-Main)
      Tasks: 10 (limit: 3167)
     Memory: 1.0G
     CGroup: /system.slice/suricata.service
             └─813625 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0

Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "--- process ---"
--- process ---
root@imx8mp-var-dart:~# ps aux | grep '[s]uricata'
root      813625 74.3 30.8 1725252 1136884 ?     Ssl  09:50   4:06 /opt/suricata/lib/ld-linux-aarch64.so.1 --library-path /opt/suricata/lib /opt/suricata/bin/suricata.real -c /etc/suricata/suricata.yaml -i wlan0
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "--- local custom rules ---"
--- local custom rules ---
root@imx8mp-var-dart:~# grep -nE "SGX|10000011|10000099" /etc/suricata/rules/local.rules
1:alert icmp any any -> any any (msg:"SGX SURICATA IDS ENGINE TEST"; sid:10000011; rev:1;)
2:alert icmp any any -> any any (msg:"SGX INLINE BLOCK TEST HIGH"; priority:1; sid:10000099; rev:1;)
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "--- latest startup logs since service start ---"
--- latest startup logs since service start ---
root@imx8mp-var-dart:~# journalctl -u suricata --since "2026-06-18 09:50:50" --no-pager
Jun 18 09:50:50 imx8mp-var-dart systemd[1]: Starting Suricata IDS/IPS Engine for SG-X Guardian...
Jun 18 09:50:50 imx8mp-var-dart systemd[1]: Started Suricata IDS/IPS Engine for SG-X Guardian.
Jun 18 09:50:50 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:50:50 - <Notice> - This is Suricata version 6.0.4 RELEASE running in SYSTEM mode
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:54 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: /etc/magic, 0: Warning: using regular magic file `/usr/share/misc/magic'
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
Jun 18 09:54:55 imx8mp-var-dart suricata[813625]: 18/6/2026 -- 09:54:55 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo "--- latest suricata log proof ---"
--- latest suricata log proof ---
root@imx8mp-var-dart:~# tail -n 60 /var/log/suricata/suricata.log | grep -Ei "rules successfully loaded|rules failed|engine started|All AFP|Error|failed" || true
18/6/2026 -- 09:33:48 - <Error> - [ERRCODE: SC_ERR_INITIALIZATION(45)] - pid file '/var/run/suricata.pid' exists but appears stale. Make sure Suricata is not running and then remove /var/run/suricata.pid. Aborting!
18/6/2026 -- 09:39:36 - <Info> - 2 rule files processed. 50644 rules successfully loaded, 0 rules failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:43:35 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:43:35 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
18/6/2026 -- 09:43:35 - <Info> - All AFP capture threads are running.
18/6/2026 -- 09:50:57 - <Info> - 2 rule files processed. 50644 rules successfully loaded, 0 rules failed
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:54:54 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_DETECT_PREPARE(173)] - setting up thread local detect ctx for keyword "filemagic" failed
18/6/2026 -- 09:54:55 - <Error> - [ERRCODE: SC_ERR_MAGIC_LOAD(197)] - magic_load failed: File 5.41 supports only version 16 magic files. `/usr/share/misc/magic.mgc' is version 18
18/6/2026 -- 09:54:55 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
18/6/2026 -- 09:54:55 - <Info> - All AFP capture threads are running.
root@imx8mp-var-dart:~# # Rules load hone ka wait karo
root@imx8mp-var-dart:~# sleep 30
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Ping trigger karo
root@imx8mp-var-dart:~# ping -c 5 192.168.50.1 > /dev/null
root@imx8mp-var-dart:~# sleep 5
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Check karo
root@imx8mp-var-dart:~# grep "10000099\|INLINE BLOCK" /var/log/suricata/fast.log | tail -3
06/18/2026-09:58:06.502654  [**] [1:10000099:1] SGX INLINE BLOCK TEST HIGH [**] [Classification: (null)] [Priority: 1] {ICMP} 192.168.50.103:8 -> 192.168.50.1:0
06/18/2026-09:58:06.505423  [**] [1:10000099:1] SGX INLINE BLOCK TEST HIGH [**] [Classification: (null)] [Priority: 1] {ICMP} 192.168.50.1:0 -> 192.168.50.103:0
root@imx8mp-var-dart:~# sleep 10
root@imx8mp-var-dart:~# curl -s "http://127.0.0.1:8443/api/v1/threat/blocks" | python3 -m json.tool
{
    "blocked": [
        "192.168.50.1",
        "192.168.50.103"
    ]
}
root@imx8mp-var-dart:~# nft list chain inet sgx_threat input 2>/dev/null | grep -v "^}"
table inet sgx_threat {
        chain input {
                type filter hook input priority filter - 10; policy accept;
                ip saddr 192.168.50.103 drop
                ip saddr 192.168.50.1 drop
        }
root@imx8mp-var-dart:~# curl -s -X POST "http://127.0.0.1:8443/api/v1/threat/blocks/unblock" \
>   -H "Content-Type: application/json" \
>   -d '{"ip":"192.168.50.1"}' | python3 -m json.tool
{
    "success": true,
    "stdout": "unblocked 192.168.50.1\n",
    "stderr": "",
    "restartRequired": true,
    "timestamp": "2026-06-18T10:03:12.233967014+00:00"
}
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# curl -s -X POST "http://127.0.0.1:8443/api/v1/threat/blocks/unblock" \
>   -H "Content-Type: application/json" \
>   -d '{"ip":"192.168.50.103"}' | python3 -m json.tool
{
    "success": true,
    "stdout": "unblocked 192.168.50.103\n",
    "stderr": "",
    "restartRequired": true,
    "timestamp": "2026-06-18T10:03:12.438859736+00:00"
}
root@imx8mp-var-dart:~# grep "rule_update_hours" /etc/sgx-guardian/threat/config.yaml
rule_update_hours: 24
root@imx8mp-var-dart:~# curl -s -X POST "http://127.0.0.1:8443/api/v1/threat/rules/update" | python3 -m json.tool
{
    "success": false,
    "stdout": "",
    "stderr": "Error: suricata service failed to start: Traceback (most recent call last):\n  File \"/opt/suricata/bin/suricata-update\", line 32, in <module>\n    from suricata.update import main\nModuleNotFoundError: No module named 'suricata'\n",
    "restartRequired": true,
    "timestamp": "2026-06-18T10:04:35.928597215+00:00"
}
root@imx8mp-var-dart:~# # Current profile check karo
root@imx8mp-var-dart:~# cat /etc/profile.d/suricata.sh
export PATH="/opt/suricata/bin:$PATH"
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Python files bundle mein hain ya nahi verify karo
root@imx8mp-var-dart:~# ls /opt/suricata/lib/ | grep -i python
python3
python3.10
root@imx8mp-var-dart:~# cat >> /etc/profile.d/suricata.sh <<'EOF'
> export LD_LIBRARY_PATH="/opt/suricata/lib:$LD_LIBRARY_PATH"
> export PYTHONPATH="/opt/suricata/lib/python3.10:/opt/suricata/lib/python3:$PYTHONPATH"
> EOF
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# source /etc/profile.d/suricata.sh
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Test karo
root@imx8mp-var-dart:~# suricata-update --version
Illegal instruction
root@imx8mp-var-dart:~# # System python3 check karo
root@imx8mp-var-dart:~# which python3
/usr/bin/python3
date import main; print('OK')"
root@imx8mp-var-dart:~# python3 --version
Illegal instruction
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Suricata module system python se accessible hai?
root@imx8mp-var-dart:~# PYTHONPATH="/opt/suricata/lib/python3.10:/opt/suricata/lib/python3" python3 -c "from suricata.update import main; print('OK')"
Illegal instruction
root@imx8mp-var-dart:~# echo "======================================"
======================================
g/suricata/eve.json || trueroot@imx8mp-var-dart:~# echo "VERIFY: EVE JSON ALERT PARSING"
VERIFY: EVE JSON ALERT PARSING
root@imx8mp-var-dart:~# echo "======================================"
======================================
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[1] EVE JSON file check"
[1] EVE JSON file check
root@imx8mp-var-dart:~# ls -lah /var/log/suricata/eve.json || true
Segmentation fault
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[2] Check raw alert records exist"
[2] Check raw alert records exist
root@imx8mp-var-dart:~# grep -m 3 '"event_type":"alert"' /var/log/suricata/eve.json || true
Segmentation fault
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# echo

root@imx8mp-var-dart:~# echo "[3] Count alert records"
[3] Count alert records
root@imx8mp-var-dart:~# grep -c '"event_type":"alert"' /var/log/suricata/eve.json || true
Segmentation fault
 use karta hai)-dart:~# # LD_LIBRARY_PATH hatao profile se (Suricata wrapper ko zaroorat nahi — wo khud --library-path
root@imx8mp-var-dart:~# cat > /etc/profile.d/suricata.sh <<'EOF'
> export PATH="/opt/suricata/bin:$PATH"
> EOF
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # Current shell mein bhi unset karo
root@imx8mp-var-dart:~# unset LD_LIBRARY_PATH
root@imx8mp-var-dart:~# unset PYTHONPATH
root@imx8mp-var-dart:~#
root@imx8mp-var-dart:~# # System Python3 wapis theek hua?
root@imx8mp-var-dart:~# python3 --version
Python 3.11.2
root@imx8mp-var-dart:~#








