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
      # If destination is known then
      if dst_ip in self._arp_table[dpid]:
        # Obtain its mac and port
        dst_mac, dst_port = self._arp_table[dpid][dst_ip]
        log.info("Probed ARP table for dpid: %i & IP: %s to get (%s, %i)" %\
          (dpid, dst_ip, dst_mac, dst_port,))
        # Add the flow rule to switch
        if dst_port != port:
          message = of.ofp_flow_mod(buffer_id=event.ofp.buffer_id)
          message.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
          message.actions.append(of.ofp_action_output(port = dst_port))
          message.match = of.ofp_match.from_packet(packet, port)
          event.connection.send(message)
      else:
        # If destination is known via other switches
        odd_ips  = ["10.0.0.1", "10.0.0.3", "10.0.0.5"]
        even_ips = ["10.0.0.2", "10.0.0.4", "10.0.0.6"]
        if pnext.srcip in odd_ips:
          # route throgh s4
          log.info("Odd IP: %s should be routed through S4" % (pnext.srcip,))
        elif pnext.srcip in even_ips:
          log.info("Even IP: %s should be routed through S4" % (pnext.srcip,))
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
