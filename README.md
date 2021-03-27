# POX-Firewall

To detect the ARP cache poisoning attack, we have extended the Pox controller with a new module that plays the firewall role. This module analyses incoming traffic and sorts the sender according to pre-defined conditions.

Our new module will work exactly as the L2 learning switch module in forwarding packets and install rules to switches, but also it will effectively analyze ARP packets and mitigate the ARP spoofing attack in a short time.

This solution is effective because the new Pox controller module analyses all ARP types and effectively detect the attack with no effects on the ARP normal work. It also considers the two ways to assign IP to the host (static and automatic using DHCP). 

Also, it prevents the controller from faked ARP flooding and stops the attacker in a very short time. 

It also includes a mechanism to block any host who wants to flood the controller with a huge number of packets and affect its decision. Our three classes mechanism provides an easy way to classify the hosts in the network, which can be used in further solutions to stop other attacks on SDN.

To apply the firewall, place "firewall.py" to "forwarding".

Run the controller with:

./pox.py forwarding.firewall openflow.discovery  samples.pretty_log log.level --DEBUG  py  