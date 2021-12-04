# tcp-block
Block Website using TCP Packet Injection on out-of-path environment

## How to use
```
syntax : tcp-block <interface> <pattern> [-r <url>]
    -r <url> : set redirect url to <url> (maxlen : 900)
sample : tcp-block wlan0 "Host: www.president.go.kr"
       : tcp-block wlan0 -a
```

## code
* Need pcap library
* I try to use `socket`, but it doesn't work.
* I don't know why but when I use the socket function, the sending packet was very slow!
* So, I made tcp-block firewall on pcap library

* `-r` option should be completed (not yet)
* See `packet.rule` to know how I made the injecting packet.


## reference
* https://github.com/godbestway/connacNFs/blob/462d7e84d3d9d73ba6ce2c9069987e035e23ec10/ori_firewall/raw_socket/raw_socket_ori.c : for raw socket sending