# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.



#======================================================================
#
#new version of the controler completely independent of interface
#repartition within switches
#
# TO BE USED WITH mobilityPackage folder MUST BE EXECUTED WITH
#--observe-link OPTION
#----------------------------------------------------------------------
#must be used with a mininet topology that has: *A stricly related
#backbone
##======================================================================

import re

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import lldp
from ryu.lib.packet.ipv6 import ipv6	
from ryu.lib.packet import icmpv6
from ryu.lib.packet.icmpv6 import nd_router_advert
from ryu.ofproto  import ether, inet
from ryu.lib import mac as mac_lib

import ryu.controller.dpset   
import ryu.controller.network

import ryu.topology.switches
import ryu.topology.event
import ryu.topology.api

from ryu.lib.mobilityPackage import mobilityTracker


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
       	super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #Dictionnary of dictionnary that associates each switch to the list of hosts under its coverage.
        #and for each host the associated switch's interface to which it's linked and the Mac @ in a tuple
        #{dpid1 :  { host1IP:(host1MAC,intfLocal1),host2IP:(host2MAC,intfLocal2)}}
        self.coveredHosts = {}
        #not used! Resolving MAC @ : dictionnary where :
        # (src_dp_id,src_port_no) --> (@MAC local)
        self.mac_to_port = {}
        #switches list obtained from the app_manager
        self.switchList = []
        #links List obtained from the app_manager
        self.linkList = []
        #dictionary set up for routing purpose :
        #(datapathID,port_no) is associated to the ip address of the interface
        self.bindingList = {}
        #keep trace of the previous visited network
        self.mobTracker = mobilityTracker.MobilityTracker()

        #As no special event triggered when the systeme is on
        #main mode, the routing configuration is done at the
        #reception of the first message : then set to TRUE untill
        #the end.
        self.RoutingDone = False

        #new datastructure for allowing no strictly related switch backbone
        #dictionnary where each switch is associated to the list of its neighbor
        #{'switch1': set(['switch2', 'switch3']),'switch2': set(['switch1]),..}
        self.networkGraph={}
        
        #TTN [1/10/15]
        self.settingFlowTables = False
        

    #All ready written function
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #Datapath that has sent the OF message
        datapath = ev.msg.datapath
        #OFPROTO represents OpenFlow version used
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
 
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        #Table 0 miss entry : FORWARD TO TABLE 1

        match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #ofproto.OFPCML_NO_BUFFER)]
        insts = [parser.OFPInstructionGotoTable(1)]
        priority = 1
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,instructions=insts)
        datapath.send_msg(mod)
        #self.add_flow(datapath, 0, match, actions)
        
        #Table 1 miss entry : DROP PACKET
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, tblId=1)

        #Table 2 for routing flows caring of remote addresses

        #Table 2 miss entry : DROP PACKET
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, tblId=2)
        
    #Already written function : enable the controller to send flow 
    #instructions : action and matches to a given switch
    #
    #customized with table number : now 3 tables :
    #Table 0 : empty for normal scenario with default entry forwarded to table 1
    #only the flow related to vlan oriented tunnel for mobility management are
    #inserted in this table
    #Table 1 : all the routing flow (eg for routing ping messages) are inserted in this
    #table with default entry dropped.
    #Table 2 : exaclty the same role as table 0 but for local host forwarding
    #this table is only accessible by table 0 flows explicit forwarding in action field
    #That means MATCH(from vlan) -> ACTION(strip tag) -> MATCH(dest @) -> ACTION(routing)
    #only possible with 2 tables
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, tblId=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
 
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,instructions=inst,table_id=tblId)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,table_id=tblId)
        datapath.send_msg(mod)
        
    #ROUTING RELATED FUNCTIONS, case of none stricly related backbone:

    #function that find the possible path between 2 switches
    #uses breath first algorithm
    def bfs_paths(self, start, goal):
        graph = self.networkGraph;
        queue = [(start, [start])]
        while queue:
            (vertex, path) = queue.pop(0)
            for next in graph[vertex] - set(path):
                if next == goal:
                    yield path + [next]
                else:
                    queue.append((next, path + [next]))
    
    #function that call the previous one to get the shortest path
    def shortest_path(self, start, goal):
        try:
            return next(self.bfs_paths(start, goal))
        except StopIteration:
            return None

    #function that return the gateway to a packet when the final
    #destination is not directly conected to the relaying switch.
    #..this function is not optimized as it build all the path to the dest
    #and only select the 2nd element of the list
    def next_hop(self,start,goal):
        completePath = self.shortest_path(start,goal)
        print('path from', start ,' to ', goal , ' : ', completePath)
        #the returned path as at least of length 2 as it contains src and dest
        next_hop = completePath[1] 
        return next_hop


    #return the port number from witch the datapath with 
    #dpid = source can reach the datapath with dpid = dest
    #
    #works only to know the output interface of one switch
    #to reach another switch
    def routing(self, source, dest):
        for l in self.linkList:
            if l.src.dpid==source and l.dst.dpid==dest:
                return l.src.port_no
    
    #return the MAC address associated to DATAPATH_id and port_id
    def generateMAC(self, dpid, portid):
        addMAC = 'a6:0'+str(dpid)+':00:00:00:0'+str(portid)
        return addMAC

    #return the Local Scope IPV6 address associated to DATAPATH_id and port_id
    def generateLL(self, dpid, portid):
        addLL = 'fe80::a6ff:'+str(dpid)+':ffff:'+str(portid)
        return addLL 
        
    #return the IP forged by an host whose @ mac is hostID
    #in the network defined by prefix
    #uses STRINGS
    def forgeHostGlobalIP(self, hostID, prefix):
        arrayMAC = hostID.split(":")
        arrayMAC.insert(3,'fe')
        arrayMAC.insert(3,'ff')

        secondNumber=int(arrayMAC[0][1],16)
        #we have to set the 2nd bit of second number to one
        newSecondNumber=hex(secondNumber ^ 2 )
        
        newOctet = arrayMAC[0][0]+str(newSecondNumber[2:])
        arrayMAC[0] = newOctet
        print arrayMAC
        #aggregation 2 by 2
        globalIParray = [arrayMAC[i]+arrayMAC[i+1] for i in range(0,7,2)]

        #compression if case of 0 just after one ':'
        for index, sequence in enumerate(globalIParray):
            zerosToReplace=0
            for byte in sequence:
                if byte != '0':
                    break
                zerosToReplace=zerosToReplace+1
            #we get the number of 0 to delete
            globalIParray[index] = sequence[zerosToReplace:]

        globalIParray.insert(0,prefix+':')
        #forging string from array
        globalIPstring = ":".join(globalIParray)
        print globalIPstring
        return globalIPstring
    

    #Set up tunnel for traffic forwading in mobility handling
    def setUpTunnel(self, hostIPadd,priorDp,datapath,tunID):
        
        parserOld = priorDp.ofproto_parser
        ofpOld = priorDp.ofproto

        parserNew = datapath.ofproto_parser
        ofpNew = datapath.ofproto

        #prior Network SIDE:
        #Flow Network ---> Host :
 
        #Handling incomming packets with the old host @
        #as destination @

        priorAddress = hostIPadd
                    
        #MATCH : if incoming packets that try to reach host old @
        #match for ICMP only must be updated by the time
        matchOldInput = parserOld.OFPMatch( eth_type=0x86dd, ip_proto=58,vlan_vid=0x000, ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
        matchOldInput1 = parserOld.OFPMatch( eth_type=0x86dd, vlan_vid=0x000, ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')) #TTN
        
                    
        #ACTIONS : Decrement TTL (not enabled)+ encapsulate them in new VLAN+ updating mac @+forward them to the new router

        #Resolving next hop and output port
        nextHop1ID = self.next_hop(priorDp.id,datapath.id)
        outputPortNb = self.routing(priorDp.id,nextHop1ID)
        #set up mac addresses
        new_mac_src1 = self.generateMAC(priorDp.id,outputPortNb)
        new_mac_dst1 = self.generateMAC(nextHop1ID,self.routing(nextHop1ID,priorDp.id))

        #the value of the vlan has to set the highest of the 4 bits of OFPVID_PRESENT to 1
        #the effective value is then 0x1000 | tunnID and 0x1000 = 4096
        # Describe sum of vlan_id eg  (tunn id = 6   | OFPVID_PRESENT(0x1000=4096)) -> value = 4102 
        valTun = 4096 | tunID


        #defining action list
        actionsOldInput = [parserOld.OFPActionDecNwTtl(), parserOld.OFPActionSetField(eth_src=new_mac_src1),
                            parserOld.OFPActionSetField(eth_dst=new_mac_dst1),
                            parserOld.OFPActionPushVlan(),parserOld.OFPActionSetField(vlan_vid=valTun),parserOld.OFPActionOutput(outputPortNb) ]
    
        #Pushing flow not considering BUFFER ID
        self.add_flow(priorDp, 65535, matchOldInput, actionsOldInput)
        self.add_flow(priorDp, 65535, matchOldInput1, actionsOldInput)#TTN

        #Flow Network <--- Host
        
        #Handling packets that comes from the tunnel

        #MATCH : packets from vlan
        matchOldOutput = parserOld.OFPMatch(vlan_vid=valTun)
        #ACTIONS : desencapsulate + forward to routing table
        #Need to bypass add_flow function : because we are working with Instructions and not Actions
        #Desencapsulation
        actionsOldOutput = [parserOld.OFPActionPopVlan()]
        insts = [parserOld.OFPInstructionActions(ofpOld.OFPIT_APPLY_ACTIONS,actionsOldOutput)]
        #Forward to routing table (table 1)
        insts.append(parserOld.OFPInstructionGotoTable(1))
        mod = parserOld.OFPFlowMod(datapath=priorDp, priority=65535, match=matchOldOutput,instructions=insts)
        priorDp.send_msg(mod)

        #New Network Side:
        #Flow Network <--- Host:
        
        #Handling outgoing packets with old host @
        #as source @
                    
        #MATCH : if outcoming packets with host old @ as src @
        #match for ICMP only must be updated by the time
        matchNewOutput = parserNew.OFPMatch(eth_type=0x86dd, ip_proto=58, vlan_vid=0x0000, ipv6_src=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
        matchNewOutput1 = parserNew.OFPMatch(eth_type=0x86dd, vlan_vid=0x0000, ipv6_src=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')) #TTN
                    
        #ACTIONS : Decrement TTL (not enabled)+ encapsulate them in new VLAN+ updating MAC @+forward them to the new router

        #Resolving next hop
        nextHop2ID=self.next_hop(datapath.id,priorDp.id)
        #Resolving output port
        outputPortNb2 = self.routing(datapath.id,nextHop2ID)
        #set up mac addresses
        new_mac_src2 = self.generateMAC(datapath.id,outputPortNb2)
        new_mac_dst2 = self.generateMAC(nextHop2ID,self.routing(nextHop2ID,datapath.id))


        #defining action list

        actionsNewOutput = [
            parserNew.OFPActionDecNwTtl(), parserNew.OFPActionSetField(eth_src=new_mac_src2),
            parserNew.OFPActionSetField(eth_dst=new_mac_dst2),
            parserNew.OFPActionPushVlan(),parserNew.OFPActionSetField(vlan_vid=valTun),
            parserNew.OFPActionOutput(outputPortNb2) ]
                            

        #Pushing flow not considering BUFFER ID
        self.add_flow(datapath,65535,matchNewOutput, actionsNewOutput)
        self.add_flow(datapath,65535,matchNewOutput1, actionsNewOutput) #TTN

        #Flow Network --> Host:

        #Handling packets that comes from the tunnel
        #MATCH : packets that come from vlan
        matchNewInput = parserNew.OFPMatch(vlan_vid = valTun)
        
        #ACTIONS : desencapsulate + forward to routing table(again)
        #Need to bypass add_flow function : because we are working with Instructions and not Actions
        #Desencapsulation
        actionsNewInput = [parserNew.OFPActionPopVlan()]
        instsNew = [parserNew.OFPInstructionActions(ofpNew.OFPIT_APPLY_ACTIONS,actionsNewInput)]
        #Forward to remote local address table (table 2)
        instsNew.append(parserNew.OFPInstructionGotoTable(2))
        modNew = parserNew.OFPFlowMod(datapath=datapath, priority=65535, match=matchNewInput,instructions=instsNew)
        datapath.send_msg(modNew)
        

        #as no more strictely related network, tunnel may go through switches
        #they have to know how to relay packets
        crossedSwitches = self.shortest_path(priorDp.id,datapath.id)
        for index,intSwitch in enumerate(crossedSwitches[1:-1]):
            #setting index to the one corresponding to switch position in the original list
            realIndex = index + 1
            #get associated datapath
            intDp = [switch.dp for switch in self.switchList if switch.dp.id == intSwitch][0] 
            print(intSwitch ,' is intermediate tunnel node, datapath fetched : ')
            print(intDp)
            print('**********')
            parserInt = intDp.ofproto_parser
            ofpInt = intDp.ofproto
            #direction of the packet based on the position of the mobile address
            #direction resolving could be proper...
            
            #DIRECTION 1 : from old network to new visited network : INPUT

            #match : valn tagged and mobile @ is destination address 
            matchIntInput = parserInt.OFPMatch( eth_type=0x86dd, ip_proto=58, vlan_vid=valTun , ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
            matchIntInput1 = parserInt.OFPMatch( eth_type=0x86dd, vlan_vid=valTun , ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')) #TTN
            #must be forwarded to the right neighbor on the crossedSwitch list
            #Resolving output port
            nextHopID = crossedSwitches[realIndex+1]
            outputPortNbInt1 = self.routing(intDp.id,nextHopID)
            #set up mac addresses
            new_mac_srcInt1 = self.generateMAC(intDp.id,outputPortNbInt1)
            new_mac_dstInt1 = self.generateMAC(nextHopID,self.routing(nextHopID,intDp.id))
            #defining action list
            actionsIntInput = [parserInt.OFPActionDecNwTtl(), parserInt.OFPActionSetField(eth_src=new_mac_srcInt1),
                        parserInt.OFPActionSetField(eth_dst=new_mac_dstInt1),
                               parserInt.OFPActionOutput(outputPortNbInt1) ]
    
            #Pushing flow not considering BUFFER ID
            self.add_flow(intDp, 65535, matchIntInput, actionsIntInput) 
            self.add_flow(intDp, 65535, matchIntInput1, actionsIntInput)  #TTN          

            #DIRECTION 2 : from new visited network to old network : OUTPUT

            #match : valn tagged and mobile @ is source address 
            matchIntOutput = parserInt.OFPMatch( eth_type=0x86dd, ip_proto=58,  ipv6_src=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), vlan_vid=valTun )
            matchIntOutput1 = parserInt.OFPMatch( eth_type=0x86dd, ipv6_src=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), vlan_vid=valTun ) #TTN
            #must be forwarded to the left neighbor on the crossedSwitch list
            #Resolving output port
            nextHopID2 = crossedSwitches[realIndex-1]
            outputPortNbInt2 = self.routing(intDp.id,nextHopID2)
            #set up mac addresses
            new_mac_srcInt2 = self.generateMAC(intDp.id,outputPortNbInt2)
            new_mac_dstInt2 = self.generateMAC(nextHopID2,self.routing(nextHopID2,intDp.id))
            #defining action list
            actionsIntOutput = [parserInt.OFPActionDecNwTtl(), parserInt.OFPActionSetField(eth_src=new_mac_srcInt2),
                                parserInt.OFPActionSetField(eth_dst=new_mac_dstInt2),
                                parserInt.OFPActionOutput(outputPortNbInt2) ]
    
            #Pushing flow not considering BUFFER ID
            self.add_flow(intDp, 65535, matchIntOutput, actionsIntOutput)
            self.add_flow(intDp, 65535, matchIntOutput1, actionsIntOutput) #TTN
            print('setting up tunnel done between :',priorDp.id,' and :',datapath.id)


    #When the first IP packet is received by the controller, it triggers the
    #collecting of all the topology information
    def collectRoutingInfo(self):
        #All the topology informations are obtained from the app_manager
        appManager = app_manager.RyuApp()
        #Collecting switches and links informations
        self.switchList = ryu.topology.api.get_all_switch(appManager)
        #switchNames = [switch.dp.id for switch in listSwitch]
        #get_all_link() only returns links bewteen switches
        self.linkList = ryu.topology.api.get_all_link(appManager)
        print(self.linkList)
        #linksConnection = [str(link.src.dpid)+str(link.src.port_no)+str(link.dst.dpid) for link in self.linkList]
            
        #Once topology is known, addresses IP are distributed:
        #Creating backbone interfaces and binding them to port and switches
        for link in self.linkList:
            if (link.src.dpid,link.src.port_no) not in self.bindingList and (link.dst.dpid,link.dst.port_no) not in self.bindingList :
                nbrZerosSrc=3-len(str(link.src.dpid))
                nbrZerosDst=3-len(str(link.dst.dpid))
                self.bindingList[link.src.dpid,link.src.port_no] = '2000:'+str(link.src.dpid)+str(link.dst.dpid)+'::'+str(link.src.dpid)
                self.bindingList[link.dst.dpid,link.dst.port_no] = '2000:'+str(link.src.dpid)+str(link.dst.dpid)+'::'+str(link.dst.dpid)

            #populating networkGraph for routing algorithms:
            if link.src.dpid not in self.networkGraph.keys():
                self.networkGraph[link.src.dpid]=[]
            if link.dst.dpid not in self.networkGraph.keys():
                self.networkGraph[link.dst.dpid]=[]
            self.networkGraph[link.src.dpid].append(link.dst.dpid)
            self.networkGraph[link.dst.dpid].append(link.src.dpid)

            #populating networkGraph for routing algorithms:
            # if link.src not in self.networkGraph.keys():
            #     self.networkGraph[link.src]=[]
            # if link.dst not in self.networkGraph.keys():
            #     self.networkGraph[link.dst]=[]
            # self.networkGraph[link.src].append(link.dst)
            # self.networkGraph[link.dst].append(link.src)

        #when all the link have been scanned we change netorkGraph dictionnary
        #values from list to set of list in order to enable routing algorithm
        for switch in self.networkGraph.keys():
            self.networkGraph[switch]=set(self.networkGraph[switch])
        print 'network graph constructed:'
        print self.networkGraph

        #inserting local network interfaces in the binding list
        for switch in self.switchList:
            #registration of local interfaces in the bindingList is done when a neighbor solicitation is received
            #initilizing coveredHosts sub-dictionnary:
            self.coveredHosts[switch.dp.id]={}
            print ('covered host dictionnary for switch ', switch.dp.id , 'initialized')
        print('ROUTING CONFIGURATION DONE')
        print(self.bindingList)
        #The routing is done only once
        self.RoutingDone = True


    #Packet handler
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase 
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)

        #Extracting Message informations
        #Topology stuff
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        #Protocol stuff
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        i = pkt.get_protocol(ipv6)
        #if it's not related to IPV6, not considered
        if i is None:
            #Here you can get lldp packets
            print("Not an IPv6 Packet")
            return 0
        print("------------IPV6 PACKET------------")
        
        if(self.RoutingDone==False):
            #If it's the first ipv6 packet received routing must be done before
            self.collectRoutingInfo()

        pkt_type =0         
        dpid = datapath.id
        print 'DPID::{}'.format(dpid)
        itype = 0
        found = 0
        prefix =''
        
        #Examining protocols in the IP packet
        #Normal IPv6 packets
        if pkt.get_protocol(icmpv6.icmpv6) is None:
        #for p in pkt.protocols:    
            
            #TTN - Begin [1/10/15]
            if (self.settingFlowTables == True):
                #looking at destination address, finding out which is the next hope, changing MAC @ 
                ping_src = i.src
                ping_dst = i.dst
               
                #when ip dst @ is known : 3 cases:

                #destination is behind another router
                #destination is behind the current router
                #destination is the current router 
            
                #fetching all the local addresses of the current switch
                localAddressesList = [ self.bindingList[localPort] for localPort in self.bindingList.keys() if localPort[0]==dpid ]

                if ping_dst in localAddressesList :
                    print('ping addressed to the router')
                    #the ping is addressed to the switch:
                    print('..........Ping Reply sent..........')
                        
                else:
                    print('ping another host or switch received by ', dpid, 'going to', ping_dst)
    
                    #first step : finding out the destination switch
                    #now only host pinging is considered (no ping to backbone intf of remote switch)
                    extractedDomain = re.match(r"20*(?P<trgDpid>[1-9]{1,3})",ping_dst[0:4])
                    #getting the dpid covering the destination host
                    extractedDpid = int(extractedDomain.group('trgDpid'))
                    
                    if extractedDpid is None :
                        #if extractedDpid is None it mean that dest address begins with 2000:
                        #this is a backbone interface ip address
                        #
                        #extracting the switch to which this interface belongs
                        extractedDest = re.match(r".+:{1,2}(?P<trgDpid>[0-9]{1,4})$",ping_dst)
                        extractedDpid = int(extractedDest.group('trgDpid'))
    
                    #checking validity of the obtained dpid
                    if extractedDpid in [s.dp.id for s in self.switchList]:
                        print ('ping going to ', ping_dst , ' must be routed to router ', str(extractedDpid) ,' as destination domain is ', ping_dst[0:4])
                    #handle the case where no sub domain is found
                    else:
                        print ('no subdomain found deleting packet')
                        #throw exception
                        return 0
                    destDpid = extractedDpid
                    #1st case destination covering switch is the current one
                    if destDpid == dpid:
                        #checking if the ping destination is linked to one of the local interfaces
                        print('ping toward local network, resolving local interface')
                        if ping_dst not in self.coveredHosts[destDpid].keys():
                            print('destination: ', ping_dst ,' host is not linked to the domain switch, deleting packet')
                            return 0
                        #if destination host is linked to the switch, resolving the interface
                        outputIntf = self.coveredHosts[destDpid][ping_dst][1]
                        #setting new addresses MAC:
                        new_mac_src = self.generateMAC(destDpid,outputIntf)
                        new_mac_dst = self.coveredHosts[destDpid][ping_dst][0]
                        print('ping local host ', ping_dst , ' through interface ', outputIntf)
    
                    #2nd case destination covering switch is not the current one
                    else:#PING GOING OUTSIDE LOCAL NETWORK
                        #finding nexthop 
                        nextHopID = self.next_hop(dpid,destDpid)
                        #finding output interface
                        outputIntf = self.routing(dpid,nextHopID)
                        new_mac_src = self.generateMAC(dpid,outputIntf)
                        new_mac_dst = self.generateMAC(nextHopID,self.routing(nextHopID,dpid))
                        print ('ping toward neighbor ', outputIntf)
                            
                    action = [parser.OFPActionDecNwTtl(), parser.OFPActionSetField(eth_src=new_mac_src),
                              parser.OFPActionSetField(eth_dst=new_mac_dst),parser.OFPActionOutput(outputIntf) ]
                
                    match = parser.OFPMatch( eth_type=0x86dd, ip_proto=58, ipv6_dst=(ping_dst,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
                    match1 = parser.OFPMatch( eth_type=0x86dd, ip_proto=41, ipv6_dst=(ping_dst,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
                    print('ready to push flow to ',datapath)
                    #routing related flow then pushed to table 1
                    #self.add_flow(datapath, 1, match, action,tblId=1)
                    #self.add_flow(datapath, 1, match1, action,tblId=1) #TTN
                    print('flow pushed')        
                print 'test'
                
            #TTN - End
            
        else:
        #if 1>0:
            #Handling icmpv6 packets
            #if p.protocol_name == 'icmpv6':
            pkt_type=1
            if pkt_type == 1:
                print("-----------------ICMPv6-----------------")	
                icmp = pkt.get_protocols(icmpv6.icmpv6)[0]
                itype = 0
                found = 0
                prefix =''
                if icmp.type_== 133:
                    print 'Type : Router Solicitation'
                    itype = 1
                elif icmp.type_== 134:
                    print 'Type : Router Advertisement'
                    itype = 2
                elif icmp.type_== 128:
                    print 'Type : Echo Request'
                    itype = 4
                elif icmp.type_== 129:
                    print 'Type : Echo Reply'
                    itype = 5
                elif icmp.type_ ==136:
                    print 'Type : Neighbour Advertisement'
                    itype=3
                elif icmp.type_ ==135:
                    print'Type : Neighbour Solicitation'
                    itype=6
                else:
                    print 'Type : other ICMPV6 message'
                    print (icmp.type_)

        
        #mac_to_port is not used 
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        print("Details : packet in ", dpid, src, dst, in_port)
        #once protocols are known, it's time to prepare answers
 
        #temporary solution : here no authentication protocol
        #every user are granted
        found=1
        
        #In case of Router Solicitation
        if((itype == 1)&(found == 1)):
            
            #checking if the incomming port is not a backbone port:
            validIntf=True;
            for link in self.linkList:
                if (link.src.dpid,link.src.port_no) == (dpid,in_port) or (link.dst.dpid,link.dst.port_no) == (dpid,in_port):
                    validIntf = False;
                    print('local host registration : non valid input interface (belongs to backbone)')
                    break
            
            if not validIntf :
                return 0;
            
            #computing the global ipv6 address the host will forge
            nbrZeros=3-len(str(dpid))
            newPrefix='2'+'0'*nbrZeros+str(dpid)
            newAddress = self.forgeHostGlobalIP(src,newPrefix)

            #registering or updating host in the current router
            hostDetails = (eth.src,in_port)
            self.coveredHosts[dpid][newAddress]=hostDetails
            
            print ('coveredHost updated : switch ', dpid)
            print self.coveredHosts

            #registering the interface in the bindingList
            #done if the interface is not discovered already (dynamic linking),             
            if (dpid,in_port) not in self.bindingList.keys():
                self.bindingList[dpid,in_port]='2'+'0'*nbrZeros+str(dpid)+'::'+str(in_port)
                print ('bindingList updated : switch ', dpid)
                print self.bindingList

            print ('local host registration : host : ', eth.src , ' registered under ',dpid,' coverage at interface number ',in_port, 'with ip@ :', newAddress )
            #Mobility Management Procedure is fired
            
            #Asking for the list of the prior network
            #And updating it with the current one
            #host ID based on MAC address
            #the currrent datapath is also provided
            priorNetworks = self.mobTracker.getTraceAndUpdate(src,datapath);
            print('~~~~~~~~~~NODE HAS REGISTERED~~~~~~~~~~')
            print('previous networks : ')
            print (priorNetworks)
            print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

            #if the list is empty there is nothing more to do
            #if not tunnels must be set up:
            if priorNetworks is not None:
                #maintaining a list in order to know when to stop in the tunnel creation/updating
                #and in order not to create a tunnel that will be updated in the same procedure
                updatedTunnels=[]
                #creating tunnels with all the previous network and the current one
                for priorDp in priorNetworks[:-1]:
                    print('###########SETTING UP TUNNEL############')
                    #Getting new tunnel identifier, a tunnelID is build with
                    #the concatenation of the old router ID and the new router ID
                    tunID = int(str(priorDp.id)+str(datapath.id))
                    #when a already updated tunnel is met, it is skipped
                    if tunID in updatedTunnels:
                        continue;
                    #else it's registered to the list and the procedure is launched
                    updatedTunnels.append(tunID)

                    #fetching IP addr the host forged in the previous network
                    #in asking coveredHost dict with the provided MAC @
                    priorAddress = None 
                    for ipAddress in self.coveredHosts[priorDp.id].keys():
                        #comparing MAC addresses
                        if self.coveredHosts[priorDp.id][ipAddress][0]==src:
                            priorAddress=ipAddress
                            break
                    else:
                        #if the mac address is not associated to any ip address, exit
                        print('the host with mac @ : ',src,' has never visited ' , priorDp.id , ' here is its covered Hosts : ')
                        print( self.coveredHosts[priorDp.id])
                        return 0;

                    # nbrZeros=3-len(str(priorDp.id))
                    # priorPrefix='2'+'0'*nbrZeros+str(priorDp.id)
                    # #priorPrefix = str('200')+str(priorDp.id)
                    # priorAddress = self.forgeHostGlobalIP(src,priorPrefix)
                    
                    if priorDp.id != datapath.id:
                        #set up tunnel, host MAC @ is considered as identifier
                        self.setUpTunnel(priorAddress,priorDp,datapath,tunID)
                        print('tunnel set up from ', priorDp.id, ' to ', datapath.id)
                        #Each previously built address is included in a proactively pushed flow for
                        #forwarding on the input interface which is registered in table 3 of the new
                        #covering router. so that the NewInput flow forwards packets to this
                        #table to resolve the local output interface
                        #
                        #in_port is the interface to which packets comming from the tunnel have to be forwarded to
                        
                        #if the node change the interface it is linked to
                        #the switch, a new router solicitation is sent,
                        #all the tunnel are then updated and so is table 2
 
                        output_intf = in_port
                        match2 = parser.OFPMatch( eth_type=0x86dd, ip_proto=58, ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
                        match21 = parser.OFPMatch( eth_type=0x86dd, ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')) #TTN
                        #set up mac addresses
                        new_mac_src = self.generateMAC(dpid,output_intf) # TTN - Error if output_interface > 9
                        new_mac_dst = eth.src
                        print ('****New_mac_src:', new_mac_src, ':****New_mac_dst:',new_mac_dst)
                        action2 = [parser.OFPActionDecNwTtl(), parser.OFPActionSetField(eth_src=new_mac_src),
                                   parser.OFPActionSetField(eth_dst=new_mac_dst),parser.OFPActionOutput(output_intf) ]
            
                        #remote address routing related flow then pushed to table 2
                        self.add_flow(datapath, 1, match2, action2,tblId=2)
                        self.add_flow(datapath, 1, match21, action2,tblId=2) #TTN
                        print('Remote Routing Flow : prior address ', priorAddress, ' -> interface : ',output_intf,' written in switch ', datapath.id) 

                    else:
                        #if the network is back in a previously visited network
                        #redirect the tunneled flow on the local interface
                        print('Mobile node ',src,' is back to network ', dpid)
                        matchBack = datapath.ofproto_parser.OFPMatch( eth_type=0x86dd, ip_proto=58,vlan_vid=0x000, ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
                        matchBack1 = datapath.ofproto_parser.OFPMatch( eth_type=0x86dd,vlan_vid=0x000, ipv6_dst=(priorAddress,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')) #TTN
                        output_port = in_port
                        new_mac_src = self.generateMAC(priorDp.id,output_port)
                        new_mac_dst = src
                        actionsBack = [datapath.ofproto_parser.OFPActionDecNwTtl(), datapath.ofproto_parser.OFPActionSetField(eth_src=new_mac_src),
                            datapath.ofproto_parser.OFPActionSetField(eth_dst=new_mac_dst)]
                        instsBack = [datapath.ofproto_parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS,actionsBack)]
                        #Forward to normal routing table (table 1)
                        instsBack.append(datapath.ofproto_parser.OFPInstructionGotoTable(1))
                        modBack = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=65535, match=matchBack,instructions=instsBack)
                        datapath.send_msg(modBack)
                        
                        print('Tunnel flow pushed to switch ' ,datapath.id ,' to make packets going to ', priorAddress, ' going to local network again')
                                      
            #once flows are set up, router advertisement has to be sent
            #create RA including the allocated prefix (should consider multiple prefixes later) 
            #direct reply on the incomming switch port
            out_port = in_port 
            pkt_generated = packet.Packet()
            e= ethernet.ethernet(dst=str(eth.src),src=self.generateMAC(dpid,in_port), ethertype=ether.ETH_TYPE_IPV6)
    
            #AS IT IS A REPLY TO ROUTER SOLLICITATION : SOURCE @ MUST BE LOCAL SCOPE!!
            srcIP = self.generateLL(dpid,in_port)
            ip = ipv6(nxt=inet.IPPROTO_ICMPV6, src=srcIP, dst=str(i.src))
            #setting up prefix : the dependant Local Network prefix is returned
            #nbrZeros=3-len(str(dpid))
            #prefix='2'+'0'*nbrZeros+str(dpid)+'::1'
            prefix=self.bindingList[dpid,in_port]
            icmp_v6 = icmpv6.icmpv6(type_=icmpv6.ND_ROUTER_ADVERT, data=icmpv6.nd_router_advert(ch_l=64, rou_l=4, options=[icmpv6.nd_option_pi(length=4, pl=64, res1=7, val_l=86400, pre_l=14400, prefix=prefix)]))
            pkt_generated.add_protocol(e)
            pkt_generated.add_protocol(ip)
            pkt_generated.add_protocol(icmp_v6)
            pkt_generated.serialize()
            actions = [parser.OFPActionOutput(out_port)]	
            out_ra = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=0, actions=actions, data=pkt_generated.data)
            datapath.send_msg(out_ra)
            print('>>>>>>>>>> ROUTER ADVERTISEMENT SENT <<<<<<<<<<')
            return
        
        #handling neighbour solicitation
        elif itype==6:
            neighSol = pkt.get_protocols(icmpv6.icmpv6)[0]
            print (neighSol)
            opt = neighSol.data.option
            trg = neighSol.data.dst
            
            if opt is not None :
            #if opt is not None, the NS is for getting the MAC @ of a given IP @
                if isinstance(opt,ryu.lib.packet.icmpv6.nd_option_sla):
                #link layer address request

                    #check if the solicited @ is the one of the router 
                    #fetching all the local addresses and the associated port of the current switch
                    trgPort = None
                    localAddressesIntfList = [ [self.bindingList[localPort],localPort[1]] for localPort in self.bindingList.keys() if localPort[0]==dpid ]

                    addrList = [addr[0] for addr in localAddressesIntfList ]
                    if str(trg) in addrList:
                        print('resolving switch mac address')
                        index = addrList.index(str(trg))
                        trgPort = localAddressesIntfList[index][1]

                    #if no address has been found, switch checks if the asking address
                    #is one of another local host since there are now several local 
                    #interfaces under which hosts have the same prefix
                    if trgPort is None:
                        #checking if mac @ of another local host is asked
                        if str(trg) in self.coveredHosts[dpid].keys():
                            print('resolving other local host address')
                            #returning incomming port, so that the asking node
                            #will use the mac @ of the switch's interface it's linked to
                            trgPort = in_port

                    #if the request concerns the router, prepare answer:
                    if trgPort is not None :
                        #get hw@
                        hw_addr = opt.hw_src
                        #reply with a neighbor adv
                        neigh_adv = icmpv6.icmpv6(type_=icmpv6.ND_NEIGHBOR_ADVERT, data=icmpv6.nd_neighbor(res=7, dst=str(trg), option=icmpv6.nd_option_tla(hw_src=self.generateMAC(dpid,trgPort))))
                        e= ethernet.ethernet(dst=str(hw_addr),src=self.generateMAC(dpid,in_port), ethertype=ether.ETH_TYPE_IPV6)
                        #here reply with global scope @
                        srcIP = self.bindingList[dpid,in_port]
                        ip = ipv6(nxt=inet.IPPROTO_ICMPV6, src=srcIP, dst=str(i.src))
                        
                        #direct reply on the incomming switch port
                        out_port = in_port 
                        pkt_generated = packet.Packet()

                    
                        pkt_generated.add_protocol(e)
                        pkt_generated.add_protocol(ip)
                        pkt_generated.add_protocol(neigh_adv)
                        pkt_generated.serialize()                        

                        #ACTION : the NA must be forwarded on the incomming switch port
                        
                        actions = [parser.OFPActionOutput(out_port)]	
                        out_ra = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=0, actions=actions, data=pkt_generated.data)
                        datapath.send_msg(out_ra)
                        print('..........neighbor advertisement sent..........')
                    else:
                        print(trg, ' address neither belongs to switch or local host')
            else:
                print('neighbor solicitation conflict resolution')
                #nothing is done here all the registration porcess is now done a the reception
                #or the router solicitation

        #handling ping requests and reply
        elif itype == 4 or itype == 5:
            #looking at destination address, finding out which is the next hope, changing MAC @ 
            ping_src = i.src
            ping_dst = i.dst
            echo = pkt.get_protocols(icmpv6.icmpv6)[0];
            print(echo)
            
            #when ip dst @ is known : 3 cases:

            #destination is behind another router
            #destination is behind the current router
            #destination is the current router 
            
            #fetching all the local addresses of the current switch
            localAddressesList = [ self.bindingList[localPort] for localPort in self.bindingList.keys() if localPort[0]==dpid ]

            if ping_dst in localAddressesList :
                print('ping addressed to the router')
                #the ping is addressed to the switch:
                #if it's a request : reply
                if itype == 4:
                    #copy request data into the reply
                    reqData = echo.data
                    pingReply = icmpv6.icmpv6(type_=icmpv6.ICMPV6_ECHO_REPLY, data=reqData)
                    #direct reply on the incomming switch port
                    out_port = in_port 

                    e= ethernet.ethernet(dst=src,src=dst, ethertype=ether.ETH_TYPE_IPV6)
                    #here reply with global scope @
                    ip = ipv6(nxt=inet.IPPROTO_ICMPV6, src=str(ping_dst), dst=str(ping_src))
                    pkt_generated = packet.Packet()

                    pkt_generated.add_protocol(e)
                    pkt_generated.add_protocol(ip)
                    pkt_generated.add_protocol(pingReply)
                    print('.........................')
                    print(pkt_generated)
                    pkt_generated.serialize()
                    #ACTION : the NA must be forwarded on the incomming switch port
                    actions = [parser.OFPActionOutput(out_port)]
                    
                    out_ra = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=0, actions=actions, data=pkt_generated.data)
                    datapath.send_msg(out_ra)
                    print('..........Ping Reply sent..........')
                    
            else:
                print('ping another host or switch received by ', dpid, 'going to', ping_dst)

                #first step : finding out the destination switch
                #now only host pinging is considered (no ping to backbone intf of remote switch)
                extractedDomain = re.match(r"20*(?P<trgDpid>[1-9]{1,3})",ping_dst[0:4])
                #getting the dpid covering the destination host
                extractedDpid = int(extractedDomain.group('trgDpid'))
                
                if extractedDpid is None :
                    #if extractedDpid is None it mean that dest address begins with 2000:
                    #this is a backbone interface ip address
                    #
                    #extracting the switch to which this interface belongs
                    extractedDest = re.match(r".+:{1,2}(?P<trgDpid>[0-9]{1,4})$",ping_dst)
                    extractedDpid = int(extractedDest.group('trgDpid'))

                #checking validity of the obtained dpid
                if extractedDpid in [s.dp.id for s in self.switchList]:
                    print ('ping going to ', ping_dst , ' must be routed to router ', str(extractedDpid) ,' as destination domain is ', ping_dst[0:4])
                #handle the case where no sub domain is found
                else:
                    print ('no subdomain found deleting packet')
                    #throw exception
                    return 0
                destDpid = extractedDpid
                #1st case destination covering switch is the current one
                if destDpid == dpid:
                    #checking if the ping destination is linked to one of the local interfaces
                    print('ping toward local network, resolving local interface')
                    if ping_dst not in self.coveredHosts[destDpid].keys():
                        print('destination: ', ping_dst ,' host is not linked to the domain switch, deleting packet')
                        return 0
                    #if destination host is linked to the switch, resolving the interface
                    outputIntf = self.coveredHosts[destDpid][ping_dst][1]
                    #setting new addresses MAC:
                    new_mac_src = self.generateMAC(destDpid,outputIntf)
                    new_mac_dst = self.coveredHosts[destDpid][ping_dst][0]
                    print('ping local host ', ping_dst , ' through interface ', outputIntf)

                #2nd case destination covering switch is not the current one
                else:#PING GOING OUTSIDE LOCAL NETWORK
                    #finding nexthop 
                    nextHopID = self.next_hop(dpid,destDpid)
                    #finding output interface
                    outputIntf = self.routing(dpid,nextHopID)
                    new_mac_src = self.generateMAC(dpid,outputIntf)
                    new_mac_dst = self.generateMAC(nextHopID,self.routing(nextHopID,dpid))
                    print ('ping toward neighbor ', outputIntf)
                        
                action = [parser.OFPActionDecNwTtl(), parser.OFPActionSetField(eth_src=new_mac_src),
                          parser.OFPActionSetField(eth_dst=new_mac_dst),parser.OFPActionOutput(outputIntf) ]
            
                match = parser.OFPMatch( eth_type=0x86dd, ip_proto=58, ipv6_dst=(ping_dst,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
                match1 = parser.OFPMatch( eth_type=0x86dd, ipv6_dst=(ping_dst,'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
                
                print('ready to push flow to ',datapath)
                #routing related flow then pushed to table 1
                self.add_flow(datapath, 1, match, action,tblId=1)
                self.add_flow(datapath, 1, match1, action,tblId=1) #TTN
                print('flow pushed')        
             
            #TTN - setting flow tables - done
            self.settingFlowTables = True
                
                

        else:
            print ('')
            print("========================================")            
 
     #     elif itype!=2: #Not RS, NA, and RA			
     #    		#dpid = datapath.id
     #    		#self.mac_to_port.setdefault(dpid, {})
     #    		#self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
 
     #    		# learn a mac address to avoid FLOOD next time.
     #    		#self.mac_to_port[dpid][src] = in_port
 				
     #    		if dst in self.mac_to_port[dpid]:
     #    		    out_port = self.mac_to_port[dpid][dst]
     #    		else:
     #    		    out_port = ofproto.OFPP_FLOOD
 
 
     #    		actions = [parser.OFPActionOutput(out_port)]
     #    		# install a flow to avoid packet_in next time
     #    		if out_port != ofproto.OFPP_FLOOD:
     #    		    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
     #    		    # flow_mod & packet_out
     #    		    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
     #    			self.add_flow(datapath, 1, match, actions, msg.buffer_id)
     #    			return
     #    		    else:
     #    			self.add_flow(datapath, 1, match, actions)
     #    		data = None
     #    		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
     #    		    data = msg.data
 		
 
     #    		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
     #    					          in_port=in_port, actions=actions, data=data)
 
     #    		datapath.send_msg(out)
     #    		return  
 
     #    else: # not ICMPv6 packet.
     # # should be verify later
     #    	#dpid = datapath.id
     #    	#self.mac_to_port.setdefault(dpid, {})
     #    	#self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
     #    	# learn a mac address to avoid FLOOD next time.
     #    	#self.mac_to_port[dpid][src] = in_port
 				
     #    	if dst in self.mac_to_port[dpid]:
     #    	    out_port = self.mac_to_port[dpid][dst]
     #    	else:
     #    	    out_port = ofproto.OFPP_FLOOD
 
     #    	actions = [parser.OFPActionOutput(out_port)]
     #    	# install a flow to avoid packet_in next time
     #    	if out_port != ofproto.OFPP_FLOOD:
     #    	    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
     #    	    # verify if we have a valid buffer_id, if yes avoid to send both
     #    	    # flow_mod & packet_out
     #    	    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
     #    		self.add_flow(datapath, 1, match, actions, msg.buffer_id)
     #    		return
     #    	    else:
     #    		self.add_flow(datapath, 1, match, actions)
     #    	data = None
     #    	if msg.buffer_id == ofproto.OFP_NO_BUFFER:
     #    	    data = msg.data
 
     #    	out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
     #    	datapath.send_msg(out)
     #    	return
     
