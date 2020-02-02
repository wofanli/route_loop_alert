# route_loop_alert
It is a simple script to send out an alert message once any ICMP TTL expired message is found in the fly, which indicates some kinds of route loop exists in the network.  BCC is used to filter the packet.

BCC is prerequired. My testbed is Ubuntu 16.04, and install BCC as below. 

```
echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list

apt-get update
apt-get install bcc-tools
```
