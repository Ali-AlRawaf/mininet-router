#ifndef SR_VALIDATION_H
#define SR_VALIDATION_H

int valid_arp_length(unsigned int len);
int valid_ip_length(unsigned int len);
int valid_icmp_length(unsigned int len);
int valid_ip_cksum(sr_ip_hdr_t *ip_hdr);
int valid_icmp_cksum(sr_icmp_hdr_t *icmp_hdr, uint16_t ip_len);

#endif