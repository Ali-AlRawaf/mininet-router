/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_validation.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void sr_handle_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);

  if(!valid_arp_length(len)){
    printf("DROPPED: ARP packet not long enough.\n\n");
    return;
  }

  uint16_t op = ntohs(arp_hdr->ar_op);

  if(op == arp_op_request){
    printf("Got an ARP request.\n");
    sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    if(arp_hdr->ar_tip == iface->ip){
      sr_send_arp_reply(sr, packet, iface);
      print_addr_ip_int(arp_hdr->ar_sip);
      printf(" has gotten my ARP reply\n\n");
    }
    return;
  } else if (op == arp_op_reply) {
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    print_addr_ip_int(arp_hdr->ar_sip);
    printf(" has sent me an ARP reply, forwarding any waiting packets.\n");
    pthread_mutex_lock(&sr->cache.lock);
    struct sr_packet *waiting_packet = req->packets;
    while(waiting_packet) {
      sr_forward(sr, waiting_packet->buf, waiting_packet->len, iface, arp_hdr->ar_sha);
      waiting_packet = waiting_packet->next;
    }
    pthread_mutex_lock(&sr->cache.lock);
    sr_arpreq_destroy(&sr->cache, req);
  } else {
    printf("DROPPED: ARP operation not recognized.\n\n");
    return;
  }
}

void sr_send_arp_request(struct sr_instance* sr, uint32_t ar_tip) {
  /* get length to create a new packet and get outgoing interface */
  struct sr_if *iface = sr_get_outgoing_interface(sr, ar_tip);
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *packet = (uint8_t *)calloc(1, len);

  /* populate ethernet header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  memset(eth_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  /* populate arp header */
  sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = htons(arp_op_request);
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface->ip;
  memset(arp_hdr->ar_tha, 255, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = ar_tip;

  sr_send_packet(sr, packet, len, iface->name);
}

void sr_send_arp_reply(struct sr_instance* sr, uint8_t *arpreq, struct sr_if *iface) {
  /* get length to create a new packet */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *packet = (uint8_t *)calloc(1, len);

  /* populate ethernet header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ethernet_hdr_t *arpreq_eth_hdr = (sr_ethernet_hdr_t *)arpreq;
  memcpy(eth_hdr->ether_dhost, arpreq_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = ntohs(ethertype_arp);

  /* populate arp header */
  sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);
  sr_arp_hdr_t *arpreq_arp_hdr = get_arp_hdr(arpreq);
  arp_hdr->ar_hrd = arpreq_arp_hdr->ar_hrd;
  arp_hdr->ar_pro = arpreq_arp_hdr->ar_pro;
  arp_hdr->ar_hln = arpreq_arp_hdr->ar_hln;
  arp_hdr->ar_pln = arpreq_arp_hdr->ar_pln;
  arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface->ip;
  memcpy(arp_hdr->ar_tha, arpreq_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = arpreq_arp_hdr->ar_sip;

  sr_send_packet(sr, packet, len, iface->name);
}

void sr_handle_ip_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

  printf("Got an IP packet.\n");

  /* validate length and checksum */
  if(!valid_ip_length(len) || !valid_ip_cksum(ip_hdr)) {
    printf("DROPPED: IP packet not long enough or wrong checksum.\n\n");
    return;
  }

  /* if ip packet for us, intercept and react accordingly */
  struct sr_if *interface = sr->if_list;
  while(interface) {
    if(interface->ip == ip_hdr->ip_dst) {
      printf("This packet is destined for us, intercepted.\n\n");
      sr_intercept_ip_packet(sr, packet, len, interface);
      return;
    }
    interface = interface->next;
  }

  /* packet not for us, needs forwarding */
  ip_hdr->ip_ttl--;

  if(ip_hdr->ip_ttl == 0) {
    printf("TTL is 0, sending ICMP failure back to sender out of %s\n\n", iface->name);
    sr_send_icmp_failure(sr, packet, time_exceeded, ttl_expired, iface);
    return;
  }

  /* get outgoing interface */
  struct sr_if *iface_out = sr_get_outgoing_interface(sr, ip_hdr->ip_dst);

  /* if we cant forward the packet, icmp net unreachable to the original sender */
  if(!iface_out) {
    printf("Can't forward, sending ICMP failure back to sender out of %s\n\n", iface->name);
    sr_send_icmp_failure(sr, packet, destination_unreachable, net_unreachable, iface);
    return;
  }

  /* forward and send ARP request if destination ip is not in our cache */
  struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
  if(arpentry) {
    printf("We have an ARP entry for destination. Forwarding packet.\n");
    sr_forward(sr, packet, len, iface_out, arpentry->mac);
    free(arpentry);
  } else {
    sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, iface_out->name);
    print_addr_ip_int(ip_hdr->ip_dst);
    printf(" has to send me an ARP reply, this packet will wait for it.\n");
  }
}

void sr_intercept_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

  if (ip_protocol(packet) == ip_protocol_tcp || ip_protocol(packet) == ip_protocol_udp) {
    printf("TCP or UDP protocol, sending ICMP failure back to sender out of %s\n", iface->name);
    sr_send_icmp_failure(sr, packet, destination_unreachable, port_unreachable, iface);
    return;
  } else if(ip_protocol(packet) != ip_protocol_icmp) {
    printf("DROPPED: Idk this protocol.\n");
    return;
  }

  sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);

  printf("It's an ICMP packet.\n");

  if(!valid_icmp_length(len) || !valid_icmp_cksum(icmp_hdr)) {
    printf("DROPPED: ICMP length or checksum incorrect\n");
    return;
  }

  if(icmp_hdr->icmp_type == echo_request && icmp_hdr->icmp_code == empty){
    print_addr_ip_int(ip_hdr->ip_src);
    printf(" got my ICMP echo reply.\n");

    /* reverse ethernet header */
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

    /* reverse ip header */
    uint32_t temp = ip_hdr->ip_src;
    ip_hdr->ip_src = iface->ip;
    ip_hdr->ip_dst = temp;

    /* icmp reply header and recompute checksum */
    icmp_hdr->icmp_type = echo_reply;
    icmp_hdr->icmp_code = empty;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)); 

    sr_send_packet(sr, packet, len, iface->name);
  }
}

void sr_forward(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *if_src, uint8_t *if_dst) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

  /* update ethernet header */
  memcpy(eth_hdr->ether_dhost, if_dst, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, if_src->addr, ETHER_ADDR_LEN);

  printf("Forwarding packet out of %s\n", if_src->name);

  /* recompute ip checksum */
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum((const void *)ip_hdr, sizeof(sr_ip_hdr_t)); 

  sr_send_packet(sr, packet, len, if_src->name);
}

/* 
I use this function for both type 3 and type 11 icmp because in type 3 icmp structure, the next MTU field is also unused,
making the structure identical to type 11 time exceeded messages. did not create a new struct/function only for time exceeded.
*/
void sr_send_icmp_failure(struct sr_instance *sr, uint8_t *failed_packet, uint8_t icmp_type, uint8_t icmp_code, struct sr_if *iface_out) {
  /* create new packet for icmp failure */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet = (uint8_t *)calloc(1, len);

  /* populate ethernet header by reversing source and dest hosts */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ethernet_hdr_t *failed_eth_hdr = (sr_ethernet_hdr_t *)failed_packet;

  memcpy(eth_hdr->ether_dhost, failed_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface_out->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  /* populate ip header */
  sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
  sr_ip_hdr_t *failed_ip_hdr = get_ip_hdr(failed_packet);

  ip_hdr->ip_hl = failed_ip_hdr->ip_hl;
  ip_hdr->ip_tos = failed_ip_hdr->ip_tos;
  ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_id = 0;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_v = failed_ip_hdr->ip_v;
  ip_hdr->ip_src = iface_out->ip;
  ip_hdr->ip_dst = failed_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* populate icmp header */
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  memcpy(icmp_hdr->data, failed_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  sr_send_packet(sr, packet, len, iface_out->name);
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d at %s\n",len, interface);

  /* fill in code here */

  struct sr_if *iface = sr_get_interface(sr, interface);
  uint16_t type = ethertype(packet);

  if(type == ethertype_arp)
    sr_handle_arp_packet(sr, packet, len, iface);
  else if (type == ethertype_ip)
    sr_handle_ip_packet(sr, packet, len, iface);
  else
    printf("DROPPED: neither ARP nor IP packet\n");
}/* end sr_ForwardPacket */

