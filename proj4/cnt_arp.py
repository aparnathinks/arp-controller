from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

class ARP_Responder(object):
  def __init__(self):
    # (topology dependent)initialize arp and master table with host ip-mac
    self._master_arp_table = {}
    for i in range(1,7):
      ipaddr="10.0.0.%s" % str(i)
      mac="00:00:00:00:00:0%s" % str(i)
      self._master_arp_table[IPAddr(ipaddr)]=EthAddr(mac)
    self._arp_table = {}
    #(topology specific) dpid
    self.S4=4
    self.S5=5
    
    
    core.addListeners(self)

  def _handle_GoingUpEvent(self, event):
    core.openflow.addListeners(self)

  def _handle_PacketIn(self, event):
    packet = event.parsed
    if not packet.parsed:
      return

    port  = event.port
    dpid  = event.connection.dpid
    pnext = packet.next
    
    # A new switch has connected with no arp table
    # initialize table
    if dpid not in self._arp_table:
        self._arp_table[dpid] = {}
        log.info("Initiating ARP table for dpid: %i" % (dpid,))

        if int(dpid) in [1,2,3]:
          #left node of the same leaf switch
          ipaddrL="10.0.0.%s" % str(2*int(dpid)-1)
          macL="00:00:00:00:00:0%s" % str(2*int(dpid)-1)
          #right node of the same leaf switch
          ipaddrR="10.0.0.%s" % str(2*int(dpid))
          macR="00:00:00:00:00:0%s" % str(2*int(dpid))
          self._arp_table[dpid] = {IPAddr(ipaddrL):(EthAddr(macL),3)}
          self._arp_table[dpid] = {IPAddr(ipaddrR):(EthAddr(macR),4)}
          log.info("Initiating ARP ipL: %s, macL: %s, ipR: %s, macR: %s" %\
                  (ipaddrL,macL,ipaddrR,macR))
    # If it is an IPv4 packet
    if isinstance(pnext, ipv4):    
      # Learn or update mac and port info for IP
      self._arp_table[dpid][pnext.srcip] = (packet.src, port)
      self._master_arp_table[pnext.srcip] = packet.src
      log.info("Updating ARP table for dpid: %i & IP: %s with (%s, %i)" %\
        (dpid, pnext.srcip, packet.src, port,))
      dst_ip = pnext.dstip # Find the packet destination

      
      # number hosts for computing convenience
      odd_ips  = {IPAddr('10.0.0.1'): 1, IPAddr('10.0.0.3'): 3, IPAddr('10.0.0.5'): 5}
      even_ips = {IPAddr('10.0.0.2'): 2, IPAddr('10.0.0.4'): 4, IPAddr('10.0.0.6'): 6}          

      # create msg and append destination port
      message = of.ofp_flow_mod(buffer_id=event.ofp.buffer_id)

      

      # If destination is known then
      if dst_ip in self._arp_table[dpid]:
        # Obtain its mac and port
        dst_mac, dst_port = self._arp_table[dpid][dst_ip]
        
        message.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac)) 
        #log.info("arp ref available dpid: %i & IP: %s to get (%s, %i)" %\
        #  (dpid, dst_ip, dst_mac, dst_port,))
        
        
          
        # Add the flow rule to switch
        if dst_port != port:
          message.actions.append(of.ofp_action_output(port = dst_port))
          message.match = of.ofp_match.from_packet(packet, port)
          event.connection.send(message)
        # (topology specific) if leaf switches (dpid is 1 , 2 or 3 in out case)
        if int(dpid) in [1,2,3]:
          ''' if dpid indicates leaf switch and src and dst shade that node
         directly redirect to the destination'''
          if pnext.srcip in odd_ips and \
             odd_ips[pnext.srcip]+1 == even_ips[dst_ip]:
            message.actions.append(of.ofp_action_output(port = 4))
            message.match = of.ofp_match.from_packet(packet, port)
            event.connection.send(message)
          elif pnext.srcip in even_ips and \
             even_ips[pnext.srcip]-1 == odd_ips[dst_ip]:
            message.actions.append(of.ofp_action_output(port = 3))
            message.match = of.ofp_match.from_packet(packet, port)
            event.connection.send(message)
          else:
            # route requests from odd numbered hosts through s4
            if pnext.srcip in odd_ips:
              #message.actions.append(of.ofp_action_output(port = dst_port))
              #core.openflow.sendToDPID(self.S4, message)
              message.actions.append(of.ofp_action_output(port = 1))
              message.match = of.ofp_match.from_packet(packet, port)
              log.info("Odd IP: %s should be routed through S4" % (pnext.srcip,))
              event.connection.send(message)
              
            # route requests from even numbered hosts through s5
            elif pnext.srcip in even_ips:
              #message.actions.append(of.ofp_action_output(port = dst_port))
              message.actions.append(of.ofp_action_output(port = 2))
              message.match = of.ofp_match.from_packet(packet, port)
              log.info("Even IP: %s should be routed through S5" % (pnext.srcip,))
              event.connection.send(message)
              #core.openflow.sendToDPID(self.S5, message)
              
        # If this is a spine switch send message to all other links except the port in came on
        elif int(dpid) in [4,5]:     
            lnk_ports=[1,2,3] # ports on spine connecting to links
            lnk_ports=lnk_ports.remove(event.port)
            for i in lnk_ports:
              message.actions.append(of.ofp_action_output(port = i))
              #message.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
              message.match = of.ofp_match.from_packet(packet, port)
              event.connection.send(message)
        #If it is none of the switches
        else:
          # unknown dpid
          log.info("Encountered unknown IP: %s" % (pnext.srcip,))

    # Else if it is an ARP packet
    elif isinstance(pnext, arp):
      if pnext.prototype == arp.PROTO_TYPE_IP and pnext.hwtype == arp.HW_TYPE_ETHERNET \
        and pnext.protosrc != 0:
        # Learn or update MAC & port info for IP
        self._arp_table[dpid][pnext.protosrc] = (packet.src, port)
        self._master_arp_table[pnext.protosrc] = packet.src
        log.info("ARP: Updating ARP table for dpid: %i & IP: %s with (%s, %i)" %\
          (dpid, pnext.protosrc, packet.src, port,))
        # If it is an ARP request and we know the destination
        # if pnext.opcode == arp.REQUEST and pnext.protodst in self._arp_table[dpid]:
        if pnext.opcode == arp.REQUEST and pnext.protodst in self._master_arp_table:
          # Send the ARP response
          res = arp()
          # res.hwsrc, _  = self._arp_table[dpid][pnext.protodst]
          res.hwsrc     = self._master_arp_table[pnext.protodst]
          res.hwtype    = arp.HW_TYPE_ETHERNET
          res.hwdst     = pnext.hwsrc
          res.hwlen     = pnext.hwlen
          res.prototype = arp.PROTO_TYPE_IP
          res.protodst  = pnext.protosrc
          res.protosrc  = pnext.protodst
          res.protolen  = pnext.protolen
          res.opcode    = arp.REPLY
          eth = ethernet()
          eth.type = packet.type
          eth.src  = EthAddr("%012x" % (dpid & 0xFFFFFFFFFFFF))
          eth.dst  = res.hwdst
          eth.set_payload(res)
          message = of.ofp_packet_out()
          message.in_port = port
          message.data = eth.pack()
          message.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
          event.connection.send(message)
          log.info("Responded to ARP request for dpid: %s and destination: %s" %\
            (dpid, pnext.protodst,))

def launch():
  core.registerNew(ARP_Responder)
  log.info("ARP Responder running.")
