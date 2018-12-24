# Final Skeleton
#
# Samir Shingane
# ID: 1467256
#
# Hints/Reminders from Lab 4:
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 4:
    #   - port_on_switch represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
      is_ip = packet.find('ipv4') # Searches through the packet for an IP header
      is_arp = packet.find('arp') # Searches through the packet for an ARP header
      is_icmp = packet.find('icmp') # Searches through the packet for an ICMP header
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet) # Copies field from packet to msg
      msg.data = packet_in # Places the payload of the packet into the msg 
      port_num = 0
      msg.idle_timeout = 30
      msg.hard_timeout = 30
      
      # If the packet does not contain an IP header
      if is_ip is None:    
          action = of.ofp_action_output(port = of.OFPP_FLOOD)
          msg.actions.append(action)
          self.connection.send(msg)

      else:             

          # Switch 1
          if switch_id == 1:

              if port_on_switch is 8:
                  port_num = 1
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)
                  print ("port 8")

              elif port_on_switch is 1:
                  port_num = 8
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)      
                  print("port 1")            

              else: 
                  msg.data = packet_in
                  self.connection.send(msg)   
                  print ("neither")               
          # Switch 2
          elif switch_id == 2:

              if port_on_switch is 9:
                  port_num = 1
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)
                  print ("port 9")

              elif port_on_switch is 1:
                  port_num = 9
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)   
                  print ("port 9/1")

              else: 
                  msg.data = packet_in
                  self.connection.send(msg)   
                  print ("neither")
          # Switch 3
          elif switch_id == 3:

              if port_on_switch is 10:
                  port_num = 1
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)

              elif port_on_switch is 1:
                  port_num = 10
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)   

              else: 
                  msg.data = packet_in
                  self.connection.send(msg)   

          # Switch 4
          elif switch_id == 4:
              print ("in core")

                # If the packet comes from the untrusted host
              if is_ip.srcip == '172.16.10.100': 

                  if is_icmp is None:
                       
                      # If the packet's destination is the server, drop and flood
                      if is_ip.dstip == '10.0.4.10': 
                          #action = of.ofp_action_output(port = of.OFPP_FLOOD)
                          #msg.actions.append(action)
                          msg.data = packet_in                          
                          self.connection.send(msg) 

                      elif is_ip.dstip == '10.0.1.10':
                          port_num = 2
                          action = of.ofp_action_output(port = port_num)
                          msg.actions.append(action)
                          msg.data = packet_in
                          self.connection.send(msg)

                      elif is_ip.dstip == '10.0.2.20':
                          port_num = 3
                          action = of.ofp_action_output(port = port_num)
                          msg.actions.append(action)
                          msg.data = packet_in
                          self.connection.send(msg)
                        

                      elif is_ip.dstip == '10.0.3.30':
                          port_num = 4
                          action = of.ofp_action_output(port = port_num)
                          msg.actions.append(action)
                          msg.data = packet_in
                          self.connection.send(msg)                      

                  # Check if the packet contains ICMP, drop if it does
                  else:
                      #action = of.ofp_action_output(port = of.OFPP_FLOOD)
                      msg.data = packet_in
                      self.connection.send(msg)  
                                  
              elif is_ip.dstip == '10.0.1.10':
                  port_num = 2
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)
                  print ("to h1")

              elif is_ip.dstip == '10.0.2.20':
                  port_num = 3
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)
                  print ("to h2")

              elif is_ip.dstip == '10.0.3.30':
                  port_num = 4
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)



              elif is_ip.dstip == '10.0.4.10':
                  port_num = 5
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)          

              elif is_ip.dstip == '172.16.10.100':
                  port_num = 11
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)                     

              else: 
                  msg.data = packet_in
                  self.connection.send(msg)                    

          # Switch 5
          elif switch_id == 5:
              if port_on_switch is 12:
                  port_num = 1
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)   
              elif port_on_switch is 1:
                  port_num = 12
                  action = of.ofp_action_output(port = port_num)
                  msg.actions.append(action)
                  msg.data = packet_in
                  self.connection.send(msg)   

              else: 
                  msg.data = packet_in
                  self.connection.send(msg)           

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
