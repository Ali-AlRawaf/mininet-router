***Name***

Ali Al Rawaf - 100% contribution

***Added Functionality***
Brief explanation of each function is described in comments above them. This section describes the solution process on a higher level.

1. Sending ARP replies - First thing a host will do is ask us what our IP is. I decided to handle that first. Created a new packet with enough size for an ethernet and arp header. In the ethernet header I swapped the source and destination address in the ethernet header of the request and set the ethertype to ARP. Then I populated the ARP header with the same values from the request except for the hardware addresses and opcode. Finally send the packet.

2. Intercepting IP packets - Now that my router sends ARP replies, we can start recieving some IP packets. First we look at the ones destined for us. First, we verify the packets length and IP checksum. Then, we check if the IP protocol is TCP or UDP and keep in mind that later on we need to implement port unreachable ICMP packets. If it's ICMP, then we verify the ICMP packet length and checksum. If it's an ICMP echo request, we need to send an echo reply. Since we need to preserve the ethernet and IP header and simply swap the source and destination addresses, I simply edit the request packet, set its ICMP header with echo reply and recompute its checksum, and send it right back to the requester. Rationale behind not sending an ARP request to the original requester is discuessed in detail in the *Assumption* section.

3. Sending ARP requests, handling ARP replies, forwarding - Many packets will be destined to other hosts instead of me, I need to forward these packets. We decrement the time to live here. If it becomes 0, then we must send a TTL expired ICMP message to the sender of this dead packet. First we need to send ARP requests to get the mac address of the destination IP address. We do this by looking up our ARP cache for an existing valid entry for the destination IP address. If we don't have one, we queue a request with this packet waiting on it. Every second, the queued requests are sweeped and each request is handled as follows: If the request for a particular IP address has not been replied to after 5 requests, we need to send a host unreachable ICMP packet to all IP packets waiting on this ARP reply. Otherwise, we send an ARP request and increment the times_sent field. I create an ARP request packet and populate the ethernet and ARP headers. The destination hardware addresses are set to broadcast, while the target IP address is the destination IP address of the packet to be forwarded. Upon recieving an ARP reply, the router caches the addresses, and proceeds to forward every packet waiting on that reply towards it's destination. How do we know which interface to forward out of? We use the subnet mask for each entry in our routing table (to perform a bitwise and operation on the target ip) and find a matching destination IP. The interface in the entry with the matching IP is the one we want to forward out of. This algorithm was shown in lecture slides. The algorithm returns NULL if no interface matched. In this case, we must send an ICMP net unreachable message to the sender of the packet to be forwarded.

4. Sending ICMP error packets - First we define the types and codes that we need for this assignment in sr_protocol.h. I did not differentiate between type 3 and type 11 since they have the same unused space, as we do not set the next_mtu field. We use the same t3 struct and function for all ICMP failure messages. Created a function that takes the type/code as well as the invoking packet and the interface to send the failure out of (which is the interface that the invoking packet came through). We populate a new packet with the t3 header and send it off.

***Tests***

1. client ping -c 3 server1
2. client ping -c 3 server2
3. client traceroute -n server1
4. client traceroute -n server2
5. client wget http://192.168.2.2
6. client wget http://172.64.3.10

***How to invoke timeouts & ICMP error responses***

1. If you ping once and then ping again after 15 seconds, the debug output printed to the solution terminal will indicate that another ARP request was sent.

2. If you traceroute, you can see that the very first 3 packets sent from the client have a TTL of 1, which invoke a TTL expired ICMP message from the router. Can see this ICMP packet from solution terminal output.

3. If you try to ping an address that doesn't exist in the network, or is unreachable, you will recieve net unreachable.

4. Can get port unreachable by using TCP or UDP.

5. Can get host unreachable by getting 5 ARP requests to get sent. Can achieve by creating a host that doesn't send ARP replies and trying to ping that host from another host.

***Assumption***

Only one assumption; when this router sends ICMP packets, they are always in response to a packet that was sent to it. Either this router sends an ICMP error packet, or sends ICMP echo replies. The router has sufficient information to send this packet (destination ip address, outgoing interface is the incoming interface of the packet invoking this ICMP packet to be sent, destination ethernet address). Therefore we do not send an ARP request. My rationale for why this is fine is because we are not pulling addresses from an ARP entry when we send these ICMP packets. We create ICMP error packets with addresses pulled from the packet that contains/invoked the failure. When we create ICMP echo requests we swap the source and destination ethernet addresses in the ethernet header. It is bad practice to never update an ARP entry due to the risk of ARP spoofing/poisoning, and the 15 second timeout helps to mitigate this risk. Since we do not refer to an ARP entry when sending ICMP packets, we do not run this risk. That is why I believe that sending an ARP request back to the host is unnecessary when the router is required to send an ICMP packet.