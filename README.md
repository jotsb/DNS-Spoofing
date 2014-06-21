DNS-Spoofing
============

##Objective:
The goal of this assignment is to create a proof of concept DNS spoofing application using Ruby.
 
 
##Constraints:
- The application must simply sense an HTML DNS Query and respond with a crafted Response answer, which will direct the target system to your own website. <br />
- Testing must be performed on your own local network.<br />
- The program must handle arbitrary domain name strings and craft a spoofed response.
 
 
##Assignment:
For this assignment we have created a DNS Spoofing application that is written in Ruby. Our application functions by using ARP Spoofing as a base attack method, this allows packets to be captured by the attacking machine. Then once the victim machine sends a DNS request packet out, our application will capture the packet then craft a custom DNS response packet that will be sent to the target machine. When the victim machine receives this spoofed DNS packet it will treat it as a legitimate DNS response and forward all traffic to the specified host server. All other DNS packets that are sent to the victim machine will be discarded because the first response had already been accepted.
