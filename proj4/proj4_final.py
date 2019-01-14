from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

# Global Variables
s4_up = True
s5_up = True
dpids = {}
link_dpids = {}
sw_rules = [[[0 for dst in range(7)] for src in range(7)] for dpid in range(6)]

# Generates IP Address for host
def host_ip(host):
    return IPAddr("10.0.0." + str(host))

# Generates Mac Address for host
def host_eth(host):
    return EthAddr("00000000000" + str(host))

# Checks if both hosts are connected to same leaf switch
def same_switch(h1, h2):
    return (h1%2 == 0 and (h1 - h2) == 1) or (h1%2 == 1 and (h2 - h1) == 1)

# Generate an ARP response packet from a request packet
def generate_arp_response(packet):
    pnext = packet.next

    # If it's not an ARP request
    if packet.type != packet.ARP_TYPE or pnext.opcode != arp.REQUEST:
        # log.debug("Skipping ARP response for non-ARP packet")
        return None

    # Harcoded ARP table for given topology
    arp_table = {"10.0.0.1": "000000000001", "10.0.0.2": "000000000002", "10.0.0.3": "000000000003", "10.0.0.4": "000000000004", "10.0.0.5": "000000000005", "10.0.0.6": "000000000006"}

    # If MAC entry is not available
    dst_ip = str(pnext.protodst)
    if dst_ip not in arp_table:
        log.error("Failed to find MAC for %s in ARP table" % (dst_ip,))
        return None

    # Create an ARP reply object
    res           = arp()
    res.hwsrc     = EthAddr(arp_table[dst_ip])
    res.hwdst     = packet.src
    res.hwtype    = pnext.hwtype
    # res.hwlen     = pnext.hwlen
    res.prototype = pnext.prototype
    res.protodst  = pnext.protosrc
    res.protosrc  = pnext.protodst
    # res.protolen  = pnext.protolen
    res.opcode    = arp.REPLY

    # Wrap it in an Ethernet packet
    eth           = ethernet()
    eth.type      = ethernet.ARP_TYPE
    eth.src       = packet.src
    eth.dst       = res.hwsrc
    eth.payload   = res

    # Return the packet
    return eth

def add_rule(dpid,h1,h2,link):
    global sw_rules
    sw_rules[dpid][h1][h2] = link
    # print("Added Rule %i:%i->%i=%i <-> %i"%(dpid,h1,h2,link,sw_rules[dpid][h1][h2],))

# Sets the routing rules for given topology
def set_topo_rules():
    global s4_up, s5_up
    leaves = range(1,4)
    for dpid in range(1,6):
        if dpid in leaves:
            # Leaf Switch
            odd_host = 2 * dpid - 1             # Odd host connected to switch
            evn_host = 2 * dpid                 # Even host connected to switch
            add_rule(dpid,evn_host,odd_host,3)  # h2 -> h1 via port 3 etc.
            add_rule(dpid,odd_host,evn_host,4)  # h1 -> h2 via port 4 etc.
            # List of all hosts not directly connected to this switch
            other_hosts = set(range(1,7)) - set([odd_host,evn_host])
            for host in other_hosts:
                add_rule(dpid,host,odd_host,3)  # hx -> h1 via port 3 etc.
                add_rule(dpid,host,evn_host,4)  # hx -> h2 via port 4 etc.
                if s4_up:
                    add_rule(dpid,odd_host,host,1)  # Trafic from odd host goes through S4
                else:
                    add_rule(dpid,odd_host,host,2)  # If S4 is down, flow through S5
                if s5_up:
                    add_rule(dpid,evn_host,host,2)  # Trafic from even host goes through S5
                else:
                    add_rule(dpid,evn_host,host,1)  # If S5 is down, flow through S4
        else:
            # Spine Switch
            for src_sw in leaves:
                src_odd = 2 * src_sw - 1            # Odd host connected to src switch
                src_evn = 2 * src_sw                # Even host connected to src switch
                for dst_sw in leaves:
                    if src_sw != dst_sw:            # Do not interfere for identical switches
                        dst_odd = 2 * dst_sw - 1    # Odd host connected to dest switch
                        dst_evn = 2 * dst_sw        # Even host connected to dest switch
                        # Direct all traffic to dest switch's hosts via dest switch
                        if dpid == 4 or (dpid == 5 and not s4_up):
                            add_rule(dpid,src_odd,dst_odd,dst_sw)
                            add_rule(dpid,src_odd,dst_evn,dst_sw)
                            add_rule(dpid,dst_odd,src_odd,src_sw)
                            add_rule(dpid,dst_odd,src_evn,src_sw)
                        if dpid == 5 or (dpid == 4 and not s5_up):
                            add_rule(dpid,src_evn,dst_odd,dst_sw)
                            add_rule(dpid,src_evn,dst_evn,dst_sw)
                            add_rule(dpid,dst_evn,src_odd,src_sw)
                            add_rule(dpid,dst_evn,src_evn,src_sw)

def _handle_ConnectionUp(event):
    global link_dpids
    link_dpids[event.connection.dpid] = event.dpid

def _handle_PortStatus(event):
    global s4_up, s5_up
    desc = event.ofp.desc
    if desc.state == 1 and desc.config == 1:
        log.info("Link failed for DPID:%i at port %i" % (event.dpid,event.port,))
        # Check which link went down
        if event.dpid == 4:
            s4_up = False
        elif event.dpid == 5:
            s5_up = False
        else:
            log.error("Unexpected link failure for DPID:%i" % (event.dpid,))
        # Delete message flow rules
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        for connection in core.openflow.connections:
            connection.send(msg)
        set_topo_rules()
    else:
        # Not handling link going up again (for now)
        pass

def _handle_PacketIn(event):
    global link_dpids

    packet  = event.parsed
    in_port = event.port
    conn    = event.connection

    # If it is an ARP request
    eth = generate_arp_response(packet)
    if eth is not None:
        # Send the ARP response
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        conn.send(msg)
        log.debug("ARP response sent to %s" % (packet.next.protosrc,))

    # Obtain flow rules for dpid
    if conn.dpid not in link_dpids:
        log.error("Unknonw connection DPID %i" % (conn.dpid,))
        return
    dpid  = link_dpids[conn.dpid]
    rules = sw_rules[dpid]

    # Install flow rules on switch
    sources = range(1,7)
    if dpid < 4:
        # Leaf switches
        start = dpid * 2 - 1
        sources = range(start, start+2)  # Handle traffic from directly connected hosts
    elif dpid == 4 and s4_up:
        sources = range(1,7,2) # Handle traffic from odd numbered hosts
    elif dpid == 5 and s5_up:
        sources = range(2,8,2) # Handle traffic from even numbered hosts

    # Set the Rules for IP
    for src in sources:
        for dst in range(1,7):
            if src == dst or (dpid > 3 and same_switch(src, dst)):
                continue
            sw_port = rules[src][dst]
            src_ip  = host_ip(src)
            dst_ip  = host_ip(dst)
            # Set the Rule for IP
            msg = of.ofp_flow_mod()
            msg.priority = 200 if same_switch(src, dst) else 100
            msg.match.dl_type = 0x0800
            msg.match.nw_src = src_ip
            msg.match.nw_dst = dst_ip
            msg.actions.append(of.ofp_action_output(port=sw_port))
            conn.send(msg)
    # Send the current packet according to flow rules
    for src in range(1,7):
        for dst in range(1,7):
            if host_eth(src) == packet.src:
                if host_eth(dst) == packet.dst:
                    mac_msg = of.ofp_packet_out(data=event.ofp)
                    mac_msg.actions.append(of.ofp_action_output(port=sw_port))
                    conn.send(mac_msg)
    log.debug("Installed rules for DPID %i" % (dpid,))

def launch():
    set_topo_rules()
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("Capturing DPIDs")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("ARP Responder & Packet Forwarder is running")
    core.openflow.addListenerByName("PortStatus", _handle_PortStatus)
    log.info("Port Status is being monitored")

