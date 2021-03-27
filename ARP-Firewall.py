from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
import pox.lib.packet as pkt
from collections import namedtuple
import os
import csv
import threading
import time
from pox.lib.packet.arp import arp
from pox.lib.packet.dhcp import dhcp

#show messages in py component
log = core.getLogger()

#Storage list for firewall for all switches
#for each one there is an instance of the class "Firewall" , which created when called launch function 
fsw = list()

# An MAC-Data mapping table
#It has some form like : {(ARPtype,ethSrcMAC,srcIP, ethdstMAC, dstIP): count]} 
#where the key is tuple
pktData_count = {}

#verified host table to forward normal,{mac:ip} 
VHT={'00:00:00:00:00:01':'10.0.0.1','00:00:00:00:00:02':'10.0.0.2','00:00:00:00:00:03':'10.0.0.3','00:00:00:00:00:04':'10.0.0.4'}

#Banned host table to block,{mac:value} 1 for block , 0: already blocked
BHT = {}

#Candidate host table for hosts want to be verified, {mac:value} , value for future use
CHT = {}


#call methods with self (method for each switch, ex fsw[1].method()

#thread for counting
def count_packet_timer(pktData):
    # log.info("Thread : starting for packet %s", str(pktData))
    time.sleep(20)
    #reset counter after 5 seconds for similar packets
    pktData_count[pktData] = 0

def count_packets(pktData):      
        #check if it's an attack with huge number of packets
        if pktData_count[pktData] > 35 :
            log.info("Attack from %s %s",pktData[1],pktData[2])
            #pktData_count[pktData] = 0
            return True    
        #the packet exists but the counter set to 0 by the thread    
        elif pktData_count[pktData] == 1 :
            #start_counter = True
            #pktData, : pass the tuple as single paramter not 5
            # log.info("First such packet from %s %s .. Start counting",pktData[1],pktData[2])
            x = threading.Thread(target=count_packet_timer,args=(pktData,))
            #threads.append(x)
            x.start()        
        return False    
              
    
class Firewall (EventMixin):
    def __init__(self, connection):
        log.info("Firewall activated")
        self.connection = connection
        connection.addListeners(self)

		# create firewall table (src ,dst) for each switch
        #it has some form as : {(src,dst):value}
        self.firewall = {}
        
        #use this table for forwarding
        # it uses incoming packets to map MAC address to incoming port, so we can reach this host through this port
        self.mac_port = {}
        
    def block_mac (self, src,dst, duration = 0):
        """
        installs a flow to block an attacker for a while using his MAC address
        """        
        # if duration is not None:
        #    if not isinstance(duration, tuple):
        #        duration = (duration,duration)
        
        msg = of.ofp_flow_mod()
        #match = of.ofp_match(dl_type = 0x800,nw_proto = pkt.ipv4.ICMP_PROTOCOL)
        
        #block the attacker
        match = of.ofp_match()    
        
        if dst == "any":
            match.dl_src = EthAddr(src)
        elif src =="any":
            match.dl_dst = EthAddr(dst)
        else:
            match.dl_src = EthAddr(src)
            match.dl_dst = EthAddr(dst)
        #match.set_new_dst=None
        #match.nw_src = IPAddr(src)
        #match.nw_dst = IPAddr(dst)        
        #match.dl_src	Ethernet source address
        #match.dl_dst	Ethernet destination address
        #match.in_port	Switch port number the packet arrived on
        #match.nw_proto = nw_proto # 1 for ICMP or ARP opcode         
        #don't specify the action, so the default is to do nothing        
        msg.match = match
        # msg.idle_timeout = duration[0]
        # msg.idle_timeout = of.OFP_FLOW_PERMANENT
        # msg.hard_timeout = duration[1]
        #msg.hard_timeout = of.OFP_FLOW_PERMANENT        
        #default duration is PERMANENT        
        #msg.priority = 20
        self.connection.send(msg)

    # function that allows adding firewall rules into the firewall table
    #toAll param to check if we have to install the flow on all switches or not.
    def addRule (self,toAll=False, src="any", dst="any", value=True):
        if (src, dst) in self.firewall:
            log.info("Rule already exists: src %s - dst %s", src, dst)
            
        else:
            log.info("Adding firewall rule to drop: src %s - dst %s", src, dst)
            if toAll == False:
                self.firewall[(str(src), str(dst))]=value
                self.block_mac(src,dst, 10000)
            else:
                
                for i in range(0, len(fsw)):
                    fsw[i].firewall[(str(src), str(dst))]=value                    
                    fsw[i].block_mac(src,dst, 10000)


    # function that allows deleting firewall rules from the firewall table
    #toAll : similar rule on other switches
    def deleteRule (self,toAll=False, src="any", dst="any"):
            msg = of.ofp_flow_mod()      
            if dst == "any":
                msg.match.dl_src = EthAddr(src)
            elif src =="any":
                msg.match.dl_dst = EthAddr(dst)
            else:
                msg.match.dl_src = EthAddr(src)
                msg.match.dl_dst = EthAddr(dst)
            msg.command = of.OFPFC_DELETE    
            
            if toAll == False:                
               try :
                 #delete from our firewall table
                 del self.firewall[(str(src), str(dst))]
                 #
                 self.connection.send(msg)
                 log.info("Deleting firewall rule drop: src %s - dst %s , on switch: %s", src, dst, str(self.connection.dpid))
               except KeyError:
                 log.error("Cannot find in rule drop : src %s - dst %s, in switch: %s", src, dst, str(self.connection.dpid))   

            else:
                for i in range(0,len(fsw)):
                    try : 
                       del fsw[i].firewall[(src, dst)]
                       fsw[i].connection.send(msg)
                       log.info("Deleting firewall rule drop: src %s - dst %s , on switch: %s", src, dst, str(fsw[i].connection.dpid))
                    except KeyError:
                       log.error("Cannot find in rule drop : src %s - dst %s, in switch: %s", src, dst, str(fsw[i].connection.dpid))    
    
    
    #function to reset firewall
    #toAll : reset firewall on all switches
    def reset_firewall(self,toAll=False):
        #delete all rules from all switches
        if toAll == True:
            for i in range(0,len(fsw)):
                #for each switch reset its firewall
                for key in  fsw[i].firewall.keys() :
                    fsw[i].deleteRule(False,key[0],key[1])
            
        else:
            for key in self.firewall.keys():
                 self.deleteRule(False,key[0],key[1])
          
    #function to list current rules for a specific switch
    def showRules(self):
        log.info("Active Blocking Rules:") 
        for k in self.firewall.keys():
           print (str(k))
            
    #install  rules for a switch when connecting or reset       
    def _handle_ConnectionUp (self, event):
        log.info("handle connection up")
        self.connection = event.connection
        for (src, dst) in self.firewall:
            self.addRule(False,src,dst)
            log.info("A new rule (%s , %s) was installed on %s",src , dst, dpidToStr(event.dpid))
   
    #return the eth address for such a dpid
    def dpid_to_mac (self,dpid):
       return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))    
           
    def _handle_PacketIn (self , event):        
        self.connection = event.connection        
        dpid = event.connection.dpid
        inport = event.port
        mac = self.dpid_to_mac(dpid)
        #collect info from the event
        log.info("\n \n Incoming packet from switch: %s",str(dpid))
        
        # This is the parsed packet data.
        packet = event.parsed
        packet_in = event.ofp
         
        log.info("\nPacket: %s",str(packet.payload)) 
        #function to flood incoming packet
        def flood (message = None):
              """ Floods the packet """
              #an output packet
              msg = of.ofp_packet_out()
              #out of all ports except the port it came from(of.OFPP_FLOOD)
              msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
              log.info("Holding down flood for %s", dpidToStr(event.dpid))
              
              #data is the same incoming packet(here to specify what to flood)
              msg.data = event.ofp
              msg.in_port = event.port
              self.connection.send(msg)
    
        def drop (duration = None):
              """
              Drops this packet and optionally installs a flow to continue
              dropping similar ones for a while
              """
              if duration is not None:
                if not isinstance(duration, tuple):
                  duration = (duration,duration)
                msg = of.ofp_flow_mod()
                # we have defined: packet = event.parsed
                msg.match = of.ofp_match.from_packet(packet)
                
                #when the rule will expire
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                
                #ID of the buffer in which the packet is stored at the datapath
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
                
              elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)
        
        #function to make the blocking process
        def block_mac(b_hwsrc):
            BHT[b_hwsrc] = 1
            log.info("%s Added to BHT", b_hwsrc)
            # remove from VHT if exists
            try:
               del VHT[b_hwsrc]
               log.info("deleted from VHT")
            except:
               log.info("deleted from VHT")
               
               
        #our function to detect the attack
        def antiArpSpoof():
             #from getmac import get_mac_address as gma
             #print(gma())
             # if it's an ARP packet, get the payload
            arp_packet = packet.payload   
               # OPCODES
                    # REQUEST     = 1 # ARP
                    # REPLY       = 2 # ARP
                    
            ARPtype = arp_packet.opcode        
            #extract the data from the ARP payload
            #ARP Source mac address
            hwsrc = str(arp_packet.hwsrc)
            #Ethernet Source mac address
            ethhwsrc =  str(packet.src)        
            
            #ignore if any packet from the controller
            if hwsrc == "00:00:00:00:00:00":
                return False
            
            #buffered packet before the blocking
            if hwsrc in BHT :
                return True
            
            #2.check eth.src == arp.src
            #check faked packets
            if ethhwsrc != hwsrc :
                block_mac(ethhwsrc)
                return True        
                
            #ARP destination MAC address
            hwdst= str(arp_packet.hwdst)
            #Ethernet destination mac address
            ethhwdst =  str(packet.dst)   
            #Source IP address
            IPsrc = str(arp_packet.protosrc)
            #Destination IP address
            IPdst = str(arp_packet.protodst)

            #packet data 
            pktData = (ARPtype,hwsrc,IPsrc,hwdst,IPdst)
            
            #Check if the pktData_count table already has these data
            if pktData not in pktData_count.keys():
                    # log.info("It's a new packet: %s",pktData)
                    pktData_count[pktData] = 0
 
            #ignore broadcast
            #if hwdst != "00:00:00:00:00:00":
            pktData_count[pktData] += 1                   
            if count_packets(pktData)  :
                block_mac(hwsrc)
                return True     
            
            
            #if the source IP address already exists in the table
            for key,value in VHT.items():  
                
                #If  verified host
                if hwsrc == key and IPsrc == value  :
                    #If not ARP reply, forward ..
                    if ARPtype != pkt.arp.REPLY :
                        return False
                    
                    #If ARP reply
                    #check if dest in CHT
                    for keyDes,valueDes in CHT.items():  
                        if hwdst == key :
                            try:
                               del CHT[hwdst]
                               log.info("deleted from CHT")
                            except:
                               log.info("deleted from CHT")
                            break 
                                
                    return False
                
            #if not verified host
            #if ARP REPLY
            if ARPtype != pkt.arp.REQUEST:
                #attacker
                block_mac(hwsrc)
                return True
            
            #if ARP request
            #if ARP probe
            if hwdst == "00:00:00:00:00:00" and IPsrc == "0.0.0.0":
                try:
                   del VHT[hwsrc]
                   log.info("deleted from CHT")
                except:
                   log.info("deleted from CHT")
                
                #add to CHT
                CHT[hwsrc] = 1   
                log.info("Added to CHT")
                return False

            #not probe
            #if Ann  
            if hwdst == "00:00:00:00:00:00":
               
                #check host in CHT 
                for key,value in CHT.items():
                    if hwsrc == key:
                        #sleep 1 sec waiting answers from hosts
                        time.sleep(1)
                        
                        #check again if the host was removed from CHT
                        for key1,value1 in CHT.items():
                            if hwsrc == key1:
                                #add to VHT
                                VHT[hwsrc] = IPsrc
                                log.info("Added to VHT")
                                return False
                            
                        #no in CHT ---> attacker 
                        block_mac(hwsrc)
                        return True      
                 
            #not Ann ---> attacker 
            block_mac(hwsrc)
            return True
 
             
        #add tp forwarding table
        self.mac_port[packet.src] = event.port           
        
                #1.check if an ARP packet
        if packet.type == packet.ARP_TYPE:
            start_time = time.time()
            result  = antiArpSpoof()            
            if result:
                detection_time = time.time() - start_time
                log.info("Time elapsed to detect the attack: %s",detection_time)

                #block all which considered attackers
                for key, value in BHT.items() :
                    if value == 1:
                        log.info ("An ARP spoofing attack was discovered from %s" , str(key))
                        # log.info("Bloking attacker...")
                        #block incoming packets
                        self.addRule(True,key,"any")                 
                        #block outcoming packets
                        self.addRule(True,"any",key)
                        mitigation_time = time.time() - start_time
                        BHT[key] = 0
                        log.info("Time elapsed to mitigate the attack: %s",mitigation_time)
                        
                # print("66666:")
                # print(BHT)
                return  
        
        #if DHCP packet
        #if packet.type == packet.DHCP_TYPE:
        #    print("yessssssssssssss")
        print("rrrrrrrrrrrrrrrrrr")
        print(packet)
        #     dhcp_packet = packet.payload   
        #     #check if dhcp ACK and from the server
            
        #     #add to VHT
        #     VHT[dhcp_packet.hwsrc] = dhcp_packet.protosrc
        #     log.info("Added to VHT")
        #     return False
        
        if packet.dst.is_multicast:
          log.info("multicast: flooding...")
          flood()
        else:
          if packet.dst not in self.mac_port:
            flood("Port for %s unknown -- flooding" % (packet.dst,))
          else:
            port = self.mac_port[packet.dst]
            if port == event.port:            
              log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
                  % (packet.src, packet.dst, dpidToStr(event.dpid), port))
              #drop for 10 seconds
              drop(10)
              return    
           
            log.debug("installing flow for %s.%i -> %s.%i" %
                      (packet.src, event.port, packet.dst, port))
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            #for ARP packets    
            if packet.type == packet.ARP_TYPE : 
                msg.idle_timeout = 0
                msg.hard_timeout = 1
            #send the packet on this port: port = self.mac_port[packet.dst]
            msg.actions.append(of.ofp_action_output(port = port))
            msg.data = event.ofp 
            self.connection.send(msg)        
         
def launch ():
    '''    Starting the Firewall module     '''
   # core.registerNew(Firewall)
    
    def start_firewall (event):
        log.debug("Controlling %s" % (event.connection))
        fsw.append(Firewall(event.connection))
        core.Interactive.variables['fsw'] = fsw
        core.Interactive.variables['pktData_count'] = pktData_count
        core.Interactive.variables['VHT'] = VHT
        core.Interactive.variables['CHT'] = CHT
        core.Interactive.variables['BHT'] = BHT
        
    core.openflow.addListenerByName("ConnectionUp", start_firewall)
