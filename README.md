***Functionalities (All)***

1. The router must successfully route packets between the Internet and the application servers.
2. The router must correctly handle ARP requests and replies.
3. The router must correctly handle traceroutes through it (where it is not the end host) and to it (where it is the end host).
4. The router must respond correctly to ICMP echo requests.
5. The router must handle TCP/UDP packets sent to one of its interfaces. In this case the router should respond with an ICMP port unreachable.
6. The router must maintain an ARP cache whose entries are invalidated after a timeout period (timeouts should be on the order of 15 seconds).
7. The router must queue all packets waiting for outstanding ARP replies. If a host does not respond to 5 ARP requests, the queued packet is dropped and an 8.ICMP host unreachable message is sent back to the source of the queued packet.
8. The router must not needlessly drop packets (for example when waiting for an ARP reply)
9. The router must enforce guarantees on timeouts–that is, if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router. (Note: You can guarantee this by implementing the sr arpcache sweepreqs function in sr arpcache.c correctly.)

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