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
    self._arp_table = {}
    self._master_arp_table = {}
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

    # A new switch has connected
    if dpid not in self._arp_table:
      self._arp_table[dpid] = {}
      log.info("Initiating ARP table for dpid: %i" % (dpid,))

    # If it is an IPv4 packet
    if isinstance(pnext, ipv4):
      # Learn or update mac and port info for IP
      self._arp_table[dpid][pnext.srcip] = (packet.src, port)
      self._master_arp_table[pnext.srcip] = packet.src
      log.info("Updating ARP table for dpid: %i & IP: %s with (%s, %i)" %\
        (dpid, pnext.srcip, packet.src, port,))
      # Find the packet destination
      dst_ip = pnext.dstip
      
      # number hosts for computing convenience
      odd_ips  = {"10.0.0.1": 1, "10.0.0.3": 3, "10.0.0.5": 5}
      even_ips = {"10.0.0.2": 2, "10.0.0.4": 4, "10.0.0.6": 6}
      
      # create msg
      message = of.ofp_flow_mod(buffer_id=event.ofp.buffer_id)
      message.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
      
      # if dpid indicates leaf switch and src and dst shade that node
      # directly redirect to the destination
      if pnext.srcip in odd_ips and \
         odd_ips[pnext.srcip]+1 == even_ips[dst_ip]:
        message.actions.append(of.ofp_action_output(port = 4))
      if pnext.srcip in even_ips and \
         even_ips[pnext.srcip]-1 == odd_ips[dst_ip]:
        message.actions.append(of.ofp_action_output(port = 3))      
          
      # If destination is known then
      if dst_ip in self._arp_table[dpid]:
        # Obtain its mac and port
        dst_mac, dst_port = self._arp_table[dpid][dst_ip]
        log.info("Probed ARP table for dpid: %i & IP: %s to get (%s, %i)" %\
          (dpid, dst_ip, dst_mac, dst_port,))
        # Add the flow rule to switch
        if dst_port != port:
          #message = of.ofp_flow_mod(buffer_id=event.ofp.buffer_id)
          #message.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
          message.actions.append(of.ofp_action_output(port = dst_port))
          message.match = of.ofp_match.from_packet(packet, port)
          event.connection.send(message)
      # route odd leaf switches through s4 and even ones through s5
      else:        
        # (topology specific)if leaf switches (dpid is 1 , 2 or 3 in out case)
        if pnext.srcip in odd_ips and int(dpid) in [1,2,3]:
          # route throgh s4
          # (topology specific)port 1 on leaf nodes always connect to s4
          message.actions.append(of.ofp_action_output(port = 1))
          log.info("Odd IP: %s should be routed through S4" % (pnext.srcip,))
        elif pnext.srcip in even_ips:
          # (topology specific)port 2 on leaf nodes always connect to s5
          message.actions.append(of.ofp_action_output(port = 2))
          log.info("Even IP: %s should be routed through S5" % (pnext.srcip,))
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
        log.info("Updating ARP table for dpid: %i & IP: %s with (%s, %i)" %\
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
