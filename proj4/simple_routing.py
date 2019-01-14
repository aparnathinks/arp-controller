from pox.core import core
import pox.openflow.libopenflow_01 as of


# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

#use this table to add the needed entries
table = {}

# created a class to limit the scope of table and
# initialize it separately for each switch
class SimpleRouter (object):
  def __init__(self, connection):
    connection.addListeners(self)
    self.table = table.copy()

  # Handle messages the switch has sent us because it has no
  # matching rule.
  def _handle_PacketIn(self, event):
    # check if the entry is in the table or not
    # if it's not in the table, add an entry to the table
    # We don't know where the destination is yet.  So, we'll just
    # send the packet out all ports (except the one it came in on!)
    # and hope the destination is out there somewhere. :)
    # To send out all ports, we can use either of the special ports
    # OFPP_FLOOD or OFPP_ALL. 
    # if the appropriate entry is in the table, just forward the packet to that port

    packet = event.parsed

    # Add port against the source
    if packet.src not in self.table:
      self.table[packet.src] = event.port
    
    # Find destination port & message type
    if packet.dst not in self.table:
      # Flood on all ports
      port = of.OFPP_FLOOD
      message = of.ofp_packet_out()
      message.in_port = event.port
    else:
      # Send to specified port
      port = self.table[packet.dst]
      message = of.ofp_flow_mod()
      message.match = of.ofp_match.from_packet(packet, event.port)

    # Forward the message to identified port
    message.actions.append(of.ofp_action_output(port = port))
    message.data = event.ofp
    event.connection.send(message)

def _handle_ConnectionUp(event):
  SimpleRouter(event.connection)

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  log.info("Pair-Learning switch running.")
