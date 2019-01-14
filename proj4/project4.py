from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *  
from pox.lib.recoco import Timer  
from collections import defaultdict  
from pox.openflow.discovery import Discovery  
from pox.lib.util import dpid_to_str
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
import math
import time

log = core.getLogger()
Table = [[{} for x in range(5)] for y in range(3)]    
# s4 and s5 all work
for l in range(1,4):
    Temp = Table[0][l-1] 
    for i in range(1,3):
  		for j in range(1,7):
			if i+2*(l-1) != j:
				Temp[(i+2*(l-1),j)] = (i,100)
				Temp[j,(i+2*(l-1))] = (i+2,100)
    Table[0][l-1] = Temp
for l in range(4,6):
    Temp = Table[0][l-1] 
    for i in range(1,4):
		for j in range(1,7):
			if (2*i-1)!= j and (2*i)!= j:
				Temp[2*i+l-5,j] = (int(math.ceil(j/2.0)),100)
    Table[0][l-1] = Temp
# when s5 fails
for l in range(1,4):
    Temp = Table[1][l-1] 
    for i in range(1,3):
  		for j in range(1,7):
			if i+2*(l-1) != j:
				Temp[(i+2*(l-1),j)] = (1,100)
				Temp[j,(i+2*(l-1))] = (i+2,100)
    Table[1][l-1] = Temp
for l in range(4,5):
    Temp = Table[1][l-1] 
    for i in range(1,4):
			for j in range(1,7):
				if (2*i-1)!= j and (2*i)!= j:
					Temp[2*i+l-4,j] = (int(math.ceil(j/2.0)),100)
    for i in range(1,4):
		for j in range(1,7):
			if (2*i-1)!= j and (2*i)!= j:
				Temp[2*i+l-5,j] = (int(math.ceil(j/2.0)),100)
    Table[2][l-1] = Temp
# when s4 fails
for l in range(1,4):
    Temp = Table[2][l-1] 
    for i in range(1,3):
  		for j in range(1,7):
			if i+2*(l-1) != j:
				Temp[(i+2*(l-1),j)] = (2,100)
				Temp[j,(i+2*(l-1))] = (i+2,100)
    Table[2][l-1] = Temp
for l in range(5,6):
    Temp = Table[2][l-1] 
    for i in range(1,4):
			for j in range(1,7):
				if (2*i-1)!= j and (2*i)!= j:
				    Temp[2*i+l-5,j] = (int(math.ceil(j/2.0)),100)
    for i in range(1,4):
		for j in range(1,7):
			if (2*i-1)!= j and (2*i)!= j:
				Temp[2*i+l-6,j] = (int(math.ceil(j/2.0)),100)
    Table[2][l-1] = Temp
Table[0][0][(1,2)]=(4,200)
Table[0][0][(2,1)]=(3,200)
Table[0][1][(3,4)]=(4,200)
Table[0][1][(4,3)]=(3,200)
Table[0][2][(5,6)]=(4,200)
Table[0][2][(6,5)]=(3,200)
Table[1][0][(1,2)]=(4,200)
Table[1][0][(2,1)]=(3,200)
Table[1][1][(3,4)]=(4,200)
Table[1][1][(4,3)]=(3,200)
Table[1][2][(5,6)]=(4,200)
Table[1][2][(6,5)]=(3,200)
Table[2][0][(1,2)]=(4,200)
Table[2][0][(2,1)]=(3,200)
Table[2][1][(3,4)]=(4,200)
Table[2][1][(4,3)]=(3,200)
Table[2][2][(5,6)]=(4,200)
Table[2][2][(6,5)]=(3,200)
l1_dpid=0
l2_dpid=0
l3_dpid=0
s4_dpid=0
s5_dpid=0
status = 0
sw = 0
def _handle_PortStatus (event):
    global l1_dpid,l2_dpid,l3_dpid,s4_dpid,s5_dpid,status
    #print "****************PortStatus"
    #print dir(event.ofp)
    #log.info("Packet DPID: %s" % event.dpid)
    #log.info("Packet PORT: %s" % event.port)
    #log.info("Packet OFP: %s" % event.ofp)
    #log.info("Packet REAS: %s" % event.ofp.reason)
    #log.info("Packet PACK: %s" % event.ofp.pack)
    #log.info("Packet SHOW: %s" % event.ofp.show)
    #log.info("Packet CONF: %s" % event.ofp.desc.config)
    #log.info("Packet STAT: %s" % event.ofp.desc.state)
    if event.ofp.desc.state == 1 and event.ofp.desc.config == 1:    
        log.info("Link Down: DPID = %s, PORT = %s" % (event.dpid, event.port))
        linkDown = True
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        for connection in core.openflow.connections:
	        connection.send(msg)
	        #log.debug("Clearing all flows from %s." % (dpidToStr(connection.dpid),))
        if event.dpid == 4:
            status = 2
        elif event.dpid == 5:
            status = 1
    elif event.ofp.desc.state == 0 and event.ofp.desc.config == 0:
        #log.info("Link Up: DPID = %s, PORT = %s" % (event.dpid, event.port))
        linkDown = False
def _handle_ConnectionUp(event):
    global l1_dpid,l2_dpid,l3_dpid,s4_dpid,s5_dpid
    #remember the connection dpid for switch  
    #for m in event.connection.features.ports:
		#print(m.name)
		#print(event.dpid)
    aa = event.dpid
    if aa == 1:
		l1_dpid = event.connection.dpid
    elif aa == 2:
		l2_dpid = event.connection.dpid
    elif aa == 3:
		l3_dpid = event.connection.dpid
    elif aa == 4:
		#sw = 3
		s4_dpid = event.connection.dpid
    elif aa == 5:
		#sw = 4
		s5_dpid = event.connection.dpid
def _handle_PacketIn (event):
    global l1_dpid,l2_dpid,l3_dpid,s4_dpid,s5_dpid,status
    packet = event.parsed
    arp_table = {"10.0.0.1": "00:00:00:00:00:01", "10.0.0.2": "00:00:00:00:00:02", "10.0.0.3": "000000000003", "10.0.0.4": "000000000004", "10.0.0.5": "000000000005", "10.0.0.6": "000000000006"}
    if packet.type == packet.ARP_TYPE:
        a = packet.find("arp")
        if a.opcode == a.REQUEST:

            #obtain ARP request from packet and create ARP reply
            r = arp()
            r.hwtype = a.hwtype
            r.prototype = a.prototype
            r.hwsrc = EthAddr(arp_table[str(packet.payload.protodst)])# request MAC address
            r.hwdst = packet.src
            r.opcode = arp.REPLY
            r.protosrc =  packet.payload.protodst
            r.protodst = packet.payload.protosrc

            #make ethernet packet
            eth = ethernet()
            eth.type = ethernet.ARP_TYPE
            eth.dst = packet.src
            eth.src = r.hwsrc
            eth.payload = r

            #send ARP to client
            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            msg.in_port = event.port
            event.connection.send(msg)
    if event.connection.dpid==l1_dpid:
		#print("Hello")
		sw = 0
		for i in range(1,3):
			for j in range(1,7):
				if i != j :
					msg = of.ofp_flow_mod()
					msg.match.dl_type = 0x0800
					src = "10.0.0." + str(i) 
					dst = "10.0.0." + str(j)
					msg.match.nw_src = src
					msg.match.nw_dst = dst
#					print(msg)
#					print(msg.match)
#					print(status)
#					print(sw)
#					print(Table[status][sw])
#					print((i,j))
#					print(Table[status][sw][(i,j)][0])
#					print(Table[status][sw][(i,j)][1])
					outPort = Table[status][sw][(i,j)][0]
					msg.actions.append(of.ofp_action_output(port = outPort))
					msg.priority = Table[status][sw][(i,j)][1]
					event.connection.send(msg)
					# exchange i j
					msg = of.ofp_flow_mod()
					msg.match.dl_type = 0x0800
					src = "10.0.0." + str(j) 
					dst = "10.0.0." + str(i)
					msg.match.nw_src = src
					msg.match.nw_dst = dst
#					print(status)
#					print(sw)
#					print(Table[status][sw])
#					print((j,i))
#					print(Table[status][sw][(j,i)][0])
#					print(Table[status][sw][(j,i)][1])
					outPort = Table[status][sw][(j,i)][0]
					msg.actions.append(of.ofp_action_output(port = outPort))
					msg.priority = Table[status][sw][(j,i)][1]
					event.connection.send(msg)
		for i in range(1,7):
			for j in range(1,7):
				if i != j :		
					src = EthAddr("00:00:00:00:00:0"+ str(i))
					dst = EthAddr("00:00:00:00:00:0"+ str(j))
					if src == packet.src:
						if dst == packet.dst:
							outPort = Table[status][sw][(i,j)][0]
							msg1 = of.ofp_packet_out(data = event.ofp)
							msg1.actions.append(of.ofp_action_output(port = outPort))
							event.connection.send(msg1)
                                                        log.debug("Sent a message for %s -> %s" % (src, dst, ))
    elif event.connection.dpid==l2_dpid:
		sw = 1
		for i in range(3,5):
			for j in range(1,7):
				if i != j :
					msg = of.ofp_flow_mod()
					msg.match.dl_type = 0x0800
					src = "10.0.0." + str(i) 
					dst = "10.0.0." + str(j)
					msg.match.nw_src = src
					msg.match.nw_dst = dst
#					print(status)
#					print(sw)
#					print(Table[status][sw])
#					print((i,j))
#					print(Table[status][sw][(i,j)][0])
#					print(Table[status][sw][(i,j)][1])
					outPort = Table[status][sw][(i,j)][0]
					msg.actions.append(of.ofp_action_output(port = outPort))
					msg.priority = Table[status][sw][(i,j)][1]
					event.connection.send(msg)
					# exchange i j
					msg = of.ofp_flow_mod()
					msg.match.dl_type = 0x0800
					src = "10.0.0." + str(j) 
					dst = "10.0.0." + str(i)
					msg.match.nw_src = src
					msg.match.nw_dst = dst
#					print(status)
#					print(sw)
#					print(Table[status][sw])
#					print((j,i))
#					print(Table[status][sw][(j,i)][0])
#					print(Table[status][sw][(j,i)][1])
					outPort = Table[status][sw][(j,i)][0]
					msg.actions.append(of.ofp_action_output(port = outPort))
					msg.priority = Table[status][sw][(j,i)][1]
					event.connection.send(msg)
		for i in range(1,7):
			for j in range(1,7):
				if i != j :		
					src = EthAddr("00:00:00:00:00:0"+ str(i))
					dst = EthAddr("00:00:00:00:00:0"+ str(j))
					if src == packet.src:
						if dst == packet.dst:
							outPort = Table[status][sw][(i,j)][0]
							msg1 = of.ofp_packet_out(data = event.ofp)
							msg1.actions.append(of.ofp_action_output(port = outPort))
							event.connection.send(msg1)
    elif event.connection.dpid==l3_dpid:
		sw = 2
		for i in range(5,7):
			for j in range(1,7):
				if i != j :
					msg = of.ofp_flow_mod()
					msg.match.dl_type = 0x0800
					src = "10.0.0." + str(i) 
					dst = "10.0.0." + str(j)
					msg.match.nw_src = src
					msg.match.nw_dst = dst
#					print(status)
#					print(sw)
#					print(Table[status][sw])
#					print((i,j))
#					print(Table[status][sw][(i,j)][0])
#					print(Table[status][sw][(i,j)][1])
					outPort = Table[status][sw][(i,j)][0]
					msg.actions.append(of.ofp_action_output(port = outPort))
					msg.priority = Table[status][sw][(i,j)][1]
					event.connection.send(msg)
					# exchange i j
					msg = of.ofp_flow_mod()
					msg.match.dl_type = 0x0800
					src = "10.0.0." + str(j) 
					dst = "10.0.0." + str(i)
					msg.match.nw_src = src
					msg.match.nw_dst = dst
#					print(status)
#					print(sw)
#					print(Table[status][sw])
#					print((j,i))
#					print(Table[status][sw][(j,i)][0])
#					print(Table[status][sw][(j,i)][1])
					outPort = Table[status][sw][(j,i)][0]
					msg.actions.append(of.ofp_action_output(port = outPort))
					msg.priority = Table[status][sw][(j,i)][1]
					event.connection.send(msg)
		for i in range(1,7):
			for j in range(1,7):
				if i != j :		
					src = EthAddr("00:00:00:00:00:0"+ str(i))
					dst = EthAddr("00:00:00:00:00:0"+ str(j))
					if src == packet.src:
						if dst == packet.dst:
							outPort = Table[status][sw][(i,j)][0]
							msg1 = of.ofp_packet_out(data = event.ofp)
							msg1.actions.append(of.ofp_action_output(port = outPort))
							event.connection.send(msg1)
    elif event.connection.dpid==s4_dpid:
		sw = 3
		if status == 0:
			for i in range(1,7,2):
				for j in range(1,7):
					if i != j and i+1 != j:
						msg = of.ofp_flow_mod()
						msg.match.dl_type = 0x0800
						src = "10.0.0." + str(i) 
						dst = "10.0.0." + str(j)
						msg.match.nw_src = src
						msg.match.nw_dst = dst
#						print(status)
#						print(sw)
#						print(Table[status][sw])
#						print((i,j))
#						print(Table[status][sw][(i,j)][0])
#						print(Table[status][sw][(i,j)][1])
						outPort = Table[status][sw][(i,j)][0]
						msg.actions.append(of.ofp_action_output(port = outPort))
						msg.priority = Table[status][sw][(i,j)][1]
						event.connection.send(msg)
			for i in range(1,7):
				for j in range(1,7):
					if i != j :		
						src = EthAddr("00:00:00:00:00:0"+ str(i))
						dst = EthAddr("00:00:00:00:00:0"+ str(j))
						if src == packet.src:
							if dst == packet.dst:
								outPort = Table[status][sw][(i,j)][0]
								msg1 = of.ofp_packet_out(data = event.ofp)
								msg1.actions.append(of.ofp_action_output(port = outPort))
								event.connection.send(msg1)
		elif status == 1:
			for i in range(1,7):
				for j in range(1,7):
					if i != j and (i,j) != (1,2) and (i,j) != (2,1) and (i,j) != (3,4) and (i,j) != (4,3) and (i,j) != (5,6) and (i,j) != (6,5) :
						msg = of.ofp_flow_mod()
						msg.match.dl_type = 0x0800
						src = "10.0.0." + str(i) 
						dst = "10.0.0." + str(j)
						msg.match.nw_src = src
						msg.match.nw_dst = dst
#						print(status)
#						print(sw)
#						print(Table[status][sw])
#						print((i,j))
#						print(Table[status][sw][(i,j)][0])
#						print(Table[status][sw][(i,j)][1])
						outPort = Table[status][sw][(i,j)][0]
						msg.actions.append(of.ofp_action_output(port = outPort))
						msg.priority = Table[status][sw][(i,j)][1]
						event.connection.send(msg)
			for i in range(1,7):
				for j in range(1,7):
					if i != j :		
						src = EthAddr("00:00:00:00:00:0"+ str(i))
						dst = EthAddr("00:00:00:00:00:0"+ str(j))
						if src == packet.src:
							if dst == packet.dst:
								outPort = Table[status][sw][(i,j)][0]
								msg1 = of.ofp_packet_out(data = event.ofp)
								msg1.actions.append(of.ofp_action_output(port = outPort))
								event.connection.send(msg1)	
    elif event.connection.dpid==s5_dpid:
		sw = 4
		if status == 0:
			for i in range(2,8,2):
				for j in range(1,7):
					if i != j and i-1 != j:
						msg = of.ofp_flow_mod()
						msg.match.dl_type = 0x0800
						src = "10.0.0." + str(i) 
						dst = "10.0.0." + str(j)
						msg.match.nw_src = src
						msg.match.nw_dst = dst
#						print(status)
#						print(sw)
#						print(Table[status][sw])
#						print((i,j))
#						print(Table[status][sw][(i,j)][0])
#						print(Table[status][sw][(i,j)][1])
						outPort = Table[status][sw][(i,j)][0]
						msg.actions.append(of.ofp_action_output(port = outPort))
						msg.priority = Table[status][sw][(i,j)][1]
						event.connection.send(msg)
			for i in range(1,7):
				for j in range(1,7):
					if i != j :		
						src = EthAddr("00:00:00:00:00:0"+ str(i))
						dst = EthAddr("00:00:00:00:00:0"+ str(j))
						if src == packet.src:
							if dst == packet.dst:
								outPort = Table[status][sw][(i,j)][0]
								msg1 = of.ofp_packet_out(data = event.ofp)
								msg1.actions.append(of.ofp_action_output(port = outPort))
								event.connection.send(msg1)
		elif status == 2:
			for i in range(1,7):
				for j in range(1,7):
					if i != j and (i,j) != (1,2) and (i,j) != (2,1) and (i,j) != (3,4) and (i,j) != (4,3) and (i,j) != (5,6) and (i,j) != (6,5) :
						msg = of.ofp_flow_mod()
						msg.match.dl_type = 0x0800
						src = "10.0.0." + str(i) 
						dst = "10.0.0." + str(j)
						msg.match.nw_src = src
						msg.match.nw_dst = dst
#						print(status)
#						print(sw)
#						print(Table[status][sw])
#						print((i,j))
#						print(Table[status][sw][(i,j)][0])
#						print(Table[status][sw][(i,j)][1])
						outPort = Table[status][sw][(i,j)][0]
						msg.actions.append(of.ofp_action_output(port = outPort))
						msg.priority = Table[status][sw][(i,j)][1]
						event.connection.send(msg)
			for i in range(1,7):
				for j in range(1,7):
					if i != j :		
						src = EthAddr("00:00:00:00:00:0"+ str(i))
						dst = EthAddr("00:00:00:00:00:0"+ str(j))
						if src == packet.src:
							if dst == packet.dst:
								outPort = Table[status][sw][(i,j)][0]
								msg1 = of.ofp_packet_out(data = event.ofp)
								msg1.actions.append(of.ofp_action_output(port = outPort))
								event.connection.send(msg1)	
			


                

def launch ():
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  log.info("ARP RESPONDER RUNNING")
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  log.info("Conncection Up is running")
  core.openflow.addListenerByName("PortStatus", _handle_PortStatus)
  log.info("Detecting port status")




