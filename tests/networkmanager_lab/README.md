# Isolated NetworkManager lifecycle lab

This lab runs NetworkManager 1.42.4 in a disposable Debian 12 container. A veth
named `wlan1` connects it to a DHCP server in a nested Linux network namespace.
It tests activation, DHCP, reachability, deactivation, and reactivation without
changing the host network.

Run:

```bash
./tests/networkmanager_lab/run.sh
```

The container is privileged only so it can create the nested network namespace.
It uses neither host networking nor host filesystem mounts.

This is not a wireless-radio emulator: veth appears to NetworkManager as
Ethernet. Wi-Fi scan, WPA association, NXP `wlan_sdio`, and `uap0` behavior must
still be tested with `mac80211_hwsim` on a suitable Linux kernel or on board 252.
