#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_validation.h"

int valid_arp_length(unsigned int len) {
  return len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
}

int valid_ip_length(unsigned int len) {
  return len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
}

int valid_icmp_length(unsigned int len) {
  return len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
}

int valid_ip_cksum(sr_ip_hdr_t *ip_hdr){
  uint16_t given_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  int is_valid = cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == given_cksum;
  ip_hdr->ip_sum = given_cksum;
  return is_valid;
}

int valid_icmp_cksum(sr_icmp_hdr_t *icmp_hdr, uint16_t ip_len){
  uint16_t given_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  int is_valid = cksum(icmp_hdr, ntohs(ip_len) - sizeof(sr_ip_hdr_t)) == given_cksum;
  icmp_hdr->icmp_sum = given_cksum;
  return is_valid;
}