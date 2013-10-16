/*  
   tarp_net.h -- Network functions header file
 
   Copyright (C) 2005  Wesam Lootah <lootah@cse.psu.edu>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

   This software is based on previous work done by ALoR. 
   However, it has been extensively modified by the Wesam Lootah.
   Please direct your comments and questions to:

   Wesam Lootah
   lootah@cse.psu.edu

   Note: This version of TARP is NOT suited for production environments.
   This version was developed for research purposes only.
*/


#include <netinet/if_ether.h>


#define LL_ADDR_LEN 6

struct  fixed_ether_arp {
  struct  arphdr ea_hdr;          //fixed-size header 
  u_int8_t arp_sha[ETH_ALEN];    //sender hardware address 
  u_int8_t arp_spa[4];           // sender protocol address 
  u_int8_t arp_tha[ETH_ALEN];    //target hardware address 
  u_int8_t arp_tpa[4];            //target protocol address 
};

struct tarp_ticket {
  unsigned int magic;
  unsigned short ticket_type;
  unsigned short signlen;
  unsigned char ha[ETH_ALEN];
  u_int32_t pa;
  int time_from;
  int time_to;
  int time_exp;
  char sig[128];
};

/* Ethernet header */
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* Source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};



libnet_t * init_packet_injection(char *device,char *errbuf);

int send_arp_packet(libnet_t *l,struct libnet_arp_hdr *arp,unsigned char *payload,int paylen);

int get_ip(libnet_t *l);

char * get_mac(libnet_t *l);

u_int32_t str2ip(const char *ip);

char * ip2str(u_int32_t ip);

unsigned char * str2mac(const u_char *ll_addr);

char * mac2str(const u_char * mac);
