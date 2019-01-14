from pox.core import core
import pox.openflow.libopenflow_01 as of


# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()


#use this table to add the needed entries
table = {}


# Handle messages the switch has sent us because it has no
# matching rule.

def _handle_PacketIn (event):
  # check if the entry is in the table or not
  # if it's not in the table, add an entry to the table
  # We don't know where the destination is yet.  So, we'll just
  # send the packet out all ports (except the one it came in on!)
  # and hope the destination is out there somewhere. :)
  # To send out all ports, we can use either of the special ports
  # OFPP_FLOOD or OFPP_ALL. 
  # if the appropriate entry is in the table, just forward the packet to that port
  packet = event.parsed
  p_port = event.port
  p_data = event.ofp
  src_mac = packet.src
  dst_mac = packet.dst

  if src_mac not in table:
    table[src_mac] = p_port
  '''
  if packet.type == ethernet.IP_TYPE:
    ip_packet = packet.find("ipv4")
    src_ip = ip_packet.srcip
    dst_ip = ip_packet.dstip
    if src_ip not in table:
      table[src_ip] = src_port
    if dst_ip in table:
      dst_port = table[dst_ip]
    else:
      dst_port = of.OFPP_FLOOD
  '''
  if dst_mac in table:
    dst_port = table[dst_mac]
  else:
    dst_port = of.OFPP_ALL

  forward = of.ofp_action_output(port = dst_port)
  message = of.ofp_packet_out()
  message.data = p_data
  message.actions.append(forward)
  event.connection.send(message)

def launch ():
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  log.info("Pair-Learning switch running.")

