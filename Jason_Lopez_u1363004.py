# SDN Application for CS4480 PA2 Assignment
# Author: Jason Lopez
# uID: u1363004
# Date: 3/29/25

from pox.core import core
import pox

log = core.getLogger()

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr

import pox.openflow.libopenflow_01 as of

#Intercept clients seeking servers at "10.0.0.10"
# StudentLoadBalancer: A class that intercepts ARP requests made to the server from the client for redirection
#                      to one of the two available servers. The choice of servers is done in a round-robin fashion.
class StudentLoadBalancer (object):
    # __init__: Initialization for the StudentLoadBalancer class. Sets up the event listener.
    def __init__ (self):
        core.addListeners(self)

    # _handle_PacketIn: event handler that checks for when a ARP request is recieved. If the request is recieved, then
    #                   the client is connected with one of the two servers depending on round-robin load balancing.
    def _handle_PacketIn(self, event):
        global server2_cnt, server1_cnt

        packet = event.parsed
        if packet.type == packet.ARP_TYPE:
            if packet.payload.opcode == arp.REQUEST:

                log.info("Request is received")
                # Receive request
                # Remember protosrc = ip and hwsrc = mac
                requested_MAC = 0
                server_addr = 0

                arp_reply = arp()
                arp_reply.hwdst = packet.src
                arp_reply.protodst = packet.payload.protosrc
                arp_reply.opcode = arp.REPLY

                # Client only
                # Round-Robin Load Balancing
                if str(packet.payload.protodst) == "10.0.0.10":
                    log.info("Client is requesting for server at 10.0.0.10")

                    if server1_cnt == server2_cnt or server1_cnt == 0:
                        server1_cnt += 1
                        arp_reply.hwsrc = EthAddr("00:00:00:00:00:05")
                        arp_reply.protosrc = IPAddr("10.0.0.5")

                        requested_MAC = EthAddr("00:00:00:00:00:05")
                        server_addr = IPAddr("10.0.0.5")

                        # Save the information of the client for server 1
                        server1_clients.update({ packet.payload.protosrc : packet.src })
                    else:
                        server2_cnt += 1
                        arp_reply.hwsrc = EthAddr("00:00:00:00:00:06")
                        arp_reply.protosrc = IPAddr("10.0.0.6")

                        requested_MAC = EthAddr("00:00:00:00:00:06")
                        server_addr = IPAddr("10.0.0.6")

                        # Save the information of the client for server 1
                        server2_clients.update({ packet.payload.protosrc : packet.src })


                # Server only
                if packet.payload.protodst != IPAddr("10.0.0.10"):
                    log.info("Server reply is made")
                    # Request is from server 1
                    if packet.payload.protosrc == IPAddr("10.0.0.5"):
                        requested_MAC = server1_clients.get(packet.payload.protodst)
                        arp_reply.hwsrc = requested_MAC
                    # Request is from server 2
                    elif packet.payload.protosrc == IPAddr("10.0.0.6"):
                        requested_MAC = server2_clients.get(packet.payload.protodst)
                        arp_reply.hwsrc = requested_MAC

                    arp_reply.protosrc = packet.payload.protodst


                # Client only
                if packet.payload.protodst == IPAddr("10.0.0.10"):
                    log.info("Flow rules are beginning to be added.")
                    # Send flow rules for server and client.
                    # client to server flow rule
                    fm = of.ofp_flow_mod()
                    fm.match.in_port = event.port
                    fm.match.dl_type = 0x800
                    fm.match.nw_dst = server_addr

                    fm.actions.append(pox.openflow.libopenflow_01.ofp_action_nw_addr.set_dst(server_addr))
                    fm.actions.append(pox.openflow.libopenflow_01.ofp_action_nw_addr.set_src(packet.payload.protosrc))

                    # server to client flow rule
                    sm = of.ofp_flow_mod()
                    sm.match.in_port = event.port
                    sm.match.dl_type = 0x800
                    sm.match.nw_dst = packet.payload.protosrc
                    sm.match.nw_src = server_addr

                    sm.actions.append(pox.openflow.libopenflow_01.ofp_action_nw_addr.set_dst(packet.payload.protosrc))
                    sm.actions.append(pox.openflow.libopenflow_01.ofp_action_nw_addr.set_src(server_addr))

                    event.connection.send(fm)
                    event.connection.send(sm)

                # Send ARP reply to the ARP request source.
                # Set up packet.
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = packet.src
                ether.src = requested_MAC
                ether.payload = arp_reply

                log.info("Connection to send the reply has been made")

                # Set up and send message.
                msg = of.ofp_packet_out(in_port = of.OFPP_NONE)
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port = event.port))
                event.connection.send(msg)


        return

# Hardcoded MAC address for the two servers
server_one_MAC = "00:00:00:00:00:05"
server_two_MAC = "00:00:00:00:00:06"

server_one_IP = "10.0.0.5"
server_two_IP = "10.0.0.6"

# The number of clients for each server for round-robin load bearing.
server1_cnt = 0
server2_cnt = 0

# A dictionary containing the IPs associated with each client.
server2_clients = {}
server1_clients = {}

# launch: initialization for the SDN application.
def launch ():
    global server1_cnt, server2_cnt, server1_clients, server2_clients
    core.registerNew(StudentLoadBalancer)
