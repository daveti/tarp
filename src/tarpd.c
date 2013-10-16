/*  
   TARPD.c -- The TARP DAEMON
 
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

//#define DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <libnet.h>
#include <pcap.h>
#include <libnetlink.h>

#include <tarp_error.h>
#include <wl_time.h>
#include <tarp_crypto.h>
#include <tarp_hosts.h>
#include <tarp_ticket.h>
#include <tarp_capture.h>
#include <tarp_net.h>

void process_arp_request(struct libnet_arp_hdr *arp, u_int32_t ip, libnet_t *iface);
void process_arp_reply(struct libnet_arp_hdr *arp, u_int32_t ip, char *iface);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/* Globals */
u_int32_t myIP;
libnet_t *l;
char *myMAC;
unsigned char *myticket;
int siglen;
struct ip_range known_hosts[KH_MAX_RANGES];

RSA *r;
int signed_reply_count=0;
int reply_total=0;
int request_for_me=0;
int request_total=0;

#define TICKET_LEN 30
#define ADDR_PAIR_LEN 10    //MAC + IP address length
#define TICKET_OFFSET 20
#define MAGIC 0x789a0102

#define TIME_FROM 22
#define TIME_TO 26

#define SLL_HEADER_LEN 16

#define LOG_TIME 1

#define ARPOP_TARP_TICKET 5

#define MAXVLEN 200

/* ************************************************************************* 
 *                          process_new_ticket
 *************************************************************************** */
void process_tarp_ticket(struct libnet_arp_hdr *arp)
{
  u_int32_t spa, tpa;
  struct tarp_ticket * ticket;
  struct fixed_ether_arp * earp;
  int ret;

  printf("New ticket packet received\n");
  
  earp = (struct fixed_ether_arp *) arp;

  spa = *(u_int32_t *)&earp->arp_spa;
  tpa = *(u_int32_t *)&earp->arp_tpa;

  ticket = (struct tarp_ticket *) ((earp->arp_tpa)+4);

  if (ntohl(ticket->magic) != MAGIC) {
    printf("Magic test failed\n");
    return;
  }
  else {
    DEBUG_MSG("Target mac: ");
    DEBUG_MSG("%02X:%02X:%02X:%02X:%02X:%02X\n", ticket->ha[0],ticket->ha[1],ticket->ha[2]
	   ,ticket->ha[3],ticket->ha[4],ticket->ha[5]);
    DEBUG_MSG("My mac: ");
    DEBUG_MSG("%02X:%02X:%02X:%02X:%02X:%02X\n", myMAC[0],myMAC[1],myMAC[2]
	   ,myMAC[3],myMAC[4],myMAC[5]);
  }

  //check that target mac from ticket matches our mac address
  if (memcmp(myMAC, ticket->ha, 6) != 0) {
    DEBUG_MSG("MAC in ticket does not match our MAC address\n");
  }
  
  printf("signlen %d\n",siglen);
  printf("ticket len %d\n",TICKET_LEN);
  ret = verify_signature(r,siglen,earp->arp_tpa+4,TICKET_LEN);
  if (ret != 1) {
    DEBUG_MSG("Signature is not valid\n");
  }
}

/* ************************************************************************* 
 *                          process_arp_request
 *************************************************************************** */
void process_arp_request(struct libnet_arp_hdr *arp, u_int32_t ip, libnet_t *iface) 
{
#ifdef MICRO_TEST2
  wl_uint64_t t1,t2,t3,t4,t5,diff;
  wl_current_time(&t1);
#endif
  struct fixed_ether_arp *earp;
  u_int32_t tpa,spa;
  char *spa_str;
  char *tpa_str;
  u_char myaddr[arp->ar_pln];

  request_total++;

  earp = (struct fixed_ether_arp *) arp;
  tpa = *(u_int32_t *)&earp->arp_tpa;
 
  if (tpa == ip) {

    request_for_me++;

    /* WL: op is converted to network byte because the rest of the struct 
       is in network byte and that is what send_arp_packet is expecting. 
       it will actually reconvert it to host byte order 
    */
    /* change the ARPOP */
    arp->ar_op = htons(ARPOP_REPLY);  

    /* save my address */
    memcpy(myaddr, earp->arp_tpa, arp->ar_pln);     
      
    /* swap the sender and the target */
    memcpy(earp->arp_tha, earp->arp_sha, arp->ar_hln);
    memcpy(earp->arp_tpa, earp->arp_spa, arp->ar_pln);
   
    /* fill with my addresses */
    memcpy(earp->arp_sha, myMAC, arp->ar_hln);
    memcpy(earp->arp_spa, myaddr, arp->ar_pln);  
    /* MICRO: 2 micro seconds up to this point */

    send_arp_packet(iface,arp,myticket,TICKET_LEN+siglen);
    /* MICRO: 50 micro seconds upto this point*/
  }
#ifdef MICRO_TEST2
  wl_current_time(&t3);
  diff = t3-t1;
  printf("total time %llu\n",diff);
#endif
}

/* ************************************************************************* 
 *                          process_arp_reply
 *************************************************************************** */
void process_arp_reply(struct libnet_arp_hdr *arp, u_int32_t ip, char *iface) 
{
  struct fixed_ether_arp *earp;
  u_int32_t spa,tpa;
  int ret;
  int *magic;
  time_t current_time, time_from,time_to;
  u_int32_t ticket_pa;

  struct tarp_ticket * ticket;

  reply_total++;
  earp = (struct fixed_ether_arp *) arp;
  ticket = (struct tarp_ticket *) ((earp->arp_tpa)+4);
  spa = *(u_int32_t *)&earp->arp_spa;
  tpa = *(u_int32_t *)&earp->arp_tpa;
  ticket_pa = *(u_int32_t *)((earp->arp_tpa)+18);


  if (spa == ip) {
    /* do nothing, you already know what is your own IP and MAC */
    DEBUG_MSG3("Reply with my address will be ignored\n");
    return;
  }
  /* TODO: should check if the source ip is reachable directly from one 
     of my interfaces */
  if (tpa != ip) {
    DEBUG_MSG3("Reply not for me\n");
    return;
  }


  if (is_known_host(spa,known_hosts)) {
    neigh_add(earp->arp_sha, spa, iface, NUD_REACHABLE);
  }
  else { 
    //Unknow host
    /* check if this is a TARP reply by checking the MAGIC value */
    magic = (int *)((earp->arp_tpa)+4);
    if (*magic != htonl(MAGIC)) {
      DEBUG_MSG3("Unknown host %s %s sending classic arp reply\n", 
		 mac2str(earp->arp_sha), ip2str(spa));
      return;
    }
    signed_reply_count++;
    /* 2 micro sec upto this point */
    
    /* Check if ticket is cached; 
     *        if yes check time stamp on arriving ticket
     *            if newer timestamp than cached ticket
     *                if signature is valid 
     *                      cache it
     *                else
     *                      ignore reply
     *             else
     *                      old revoked ticket ignore it
     *        else
     *             ticket is not cached; if signature is valid
     *                      cache it
     *             else
     *                      ignore it
     *
     */

    /* check that IP and MAC from ARP header match the one in Ticket */
    if (spa != ticket_pa) {
      DEBUG_MSG3("IP in ARP header %0X does not match IP in ticket ",spa);
      DEBUG_MSG3("%0X ..\n",ticket_pa);
      return;
    }

    if (memcmp(earp->arp_sha, ticket->ha,ETH_ALEN) != 0) {
      DEBUG_MSG3("MAC in ARP header does not match MAC in ticket\n");
      return;
    }

    /* Check ticket time validity */
    current_time = time(NULL);
    time_from = ntohl(*(int *) ((earp->arp_tpa+4)+TIME_FROM));
    time_to = ntohl(*(int *) ((earp->arp_tpa+4)+TIME_TO));

    if ((current_time < time_from) || (current_time > time_to)) {
      /* ticket is not valid */
      DEBUG_MSG3("Ticket is expired or not yet valid\n");
      return;
    }

#ifndef DO_NOT_CACHE	  
    unsigned char * ct;
    ct = find_ticket(spa);
    if (ct == NULL)
#else
    if (1)
#endif
      {
      /* ************************************************************ */
      ret = verify_signature(r,siglen,earp->arp_tpa+4,TICKET_LEN);
      /* 119 micro sec upto this point with 2 micro sec std */
      if (ret == 1) {
        #ifndef DO_NOT_CACHE
	 cache_ticket(spa,earp->arp_sha);
        #endif
	neigh_add(earp->arp_sha, spa, iface, NUD_REACHABLE);
	/* 193 micro sec upto this point with 13 micro sec std */
	#ifdef MICRO_TEST1
	  wl_uint64_t t1;
	  wl_current_time(&t1);
	  printf("%llu\n",t1);
	#endif
      }
      else 
	{
	  DEBUG_MSG3("Ticket is NOT valid\n");
	  return;
	}
      /* ************************************************************ */
      }
    else { //Ticket in cache

      /* ticket in cache, compare timestamps */
      int timestamps_diff = compare_timestamp(spa,earp->arp_sha);
      if (timestamps_diff == 1) {
	/* ************************************************************ */
	ret = verify_signature(r,siglen,earp->arp_tpa+4,TICKET_LEN);
	if (ret == 1) {
	  cache_ticket(spa,earp->arp_sha);
	  neigh_add(earp->arp_sha, spa, iface, NUD_REACHABLE);
	  /* 193 micro sec upto this point with 13 micro sec std */
	}
	else {
	  DEBUG_MSG3("New time stamp but invalid signature\n");
	  return;
	}
	/* ************************************************************ */
      }
      else if (timestamps_diff == 0) {
	if (compare_tickets(ct,earp->arp_sha) == 1) {
	  neigh_add(earp->arp_sha, spa, iface, NUD_REACHABLE);
	  #ifdef MICRO_TEST1
	   wl_uint64_t t1;
	   wl_current_time(&t1);
	   printf("%llu\n",t1);
	  #endif
	}
	else {
	  DEBUG_MSG3("Ticket did not match the cache\n");
	  return;
	}
      }
      else {
	printf("Revoked ticket\n");
	return;
      }
    }
  }
}
/* ************************************************************************* 
 *                          process_packet
 *************************************************************************** */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  
#ifdef LOG_TIME
  wl_uint64_t t1,t2,t3,t4,t5,diff;
  wl_current_time(&t1);
#endif

  /* Define pointers for packet's attributes */
  struct libnet_arp_hdr *arp;
  struct fixed_ether_arp *earp;   
  u_char *buf;
  u_char *dmac;
  u_char *smac; 
  int len;
  static int count = 1;                   

  arp = (struct libnet_arp_hdr *)(packet + SLL_HEADER_LEN);
  earp = (struct fixed_ether_arp *)arp;
   
  /* Check that the ARP packet is for IPv4 over Ethernet */

  if ((ntohs(arp->ar_hrd) != ARPHRD_ETHER) || (ntohs(arp->ar_pro) != ETH_P_IP)) {
    return;
  }

  // Sanity checks needed, to check the packet length
  
  
  //process packet according to type
  switch(ntohs(arp->ar_op)) 
    {
    case ARPOP_REQUEST:
      process_arp_request(arp,myIP,l);
      break;
    
    case ARPOP_REPLY:
      process_arp_reply(arp,myIP,"eth0");
      break;

    case ARPOP_TARP_TICKET:
      process_tarp_ticket(arp);

    }

#ifdef LOG_TIME
  wl_current_time(&t3);
  diff = t3-t1;
  //printf("total time %llu\n",diff);
#endif

}

void print_stats() 
{
  printf("Total requests processed %d\n",request_total);
  printf("Total requests for me %d\n",request_for_me);
  printf("Total replies processed %d\n",reply_total);
  printf("Total signed replies %d\n",signed_reply_count);
}

void load_configuration(char * config_file, char * kh_file, char * pk_file, char * ticket_file)
{
  FILE * config_f;
  int c;
  char key[MAXVLEN], value[MAXVLEN];
  char * line;
  int linelen = 400;

   //open the config file
  if ((config_f = fopen(config_file, "r")) == NULL) {
    ERROR_MSG("Cannot open config file: %s\n", config_file);
    exit(0);
  }
  
  line = malloc(linelen);

  while ((c = getline(&line,&linelen,config_f)) != -1) {
    //ignore comments
     if (line[0] != '#') {
       if ((sscanf(line, "%s %s",key,value) == 2)) {
	if (strncmp(key,"public_key",MAXVLEN) == 0) {
	  strncpy(pk_file, value, MAXVLEN);  
	}
	else if (strncmp(key,"known_hosts",MAXVLEN) == 0) {
	  strncpy(kh_file, value, MAXVLEN);  
	}
	else if (strncmp(key,"ticket",MAXVLEN) == 0) {
	  strncpy(ticket_file, value, MAXVLEN);  
	}
      }
     }
  }
  DEBUG_MSG3("Public Key file = %s\n", pk_file);
  DEBUG_MSG3("Hosts file = %s\n", kh_file);
  DEBUG_MSG3("Ticket file = %s\n", ticket_file);
  free(line);
}
/* ************************************************************************* 
 *                          main
 *************************************************************************** */
int main(int argc, char *argv[])
{
  pcap_t *descr;
  char *dev;
  char errbuf[LIBNET_ERRBUF_SIZE];
  char *tmp_str;
  int ret;
  char kh_file[MAXVLEN], ticket_file[MAXVLEN], pk_file[MAXVLEN];
  char config_file[MAXVLEN];


  if (argc ==  2) {
    if (strncmp(argv[1],"-h",2) == 0) {
      fprintf(stderr,"Usage %s [config_file]\n",argv[0]);
      exit(-1);
    }
    else {
      strncpy(config_file, argv[1], MAXVLEN-1);
    }
  }
  else if (argc == 1) {
    strncpy(config_file, "/etc/tarp/tarp_config", MAXVLEN-1);
  }
  else {
    fprintf(stderr,"Usage %s [config_file]\n",argv[0]);
    exit(-1);
  }

  dev = "eth0";

  load_configuration(config_file, kh_file, pk_file, ticket_file);
 
  #ifndef DEBUG 
     daemonize();
  #endif

  handle_signals();

  descr = init_capture();
  
  if ((l = init_packet_injection(dev,errbuf)) == NULL) {
    ERROR_MSG(errbuf);
  }
  
  myIP = get_ip(l);
  myMAC = get_mac(l);

  DEBUG_MSG("INFO: Interface IP %X\n",myIP);

  disable_kernel_arp();

  r = init_crypto(pk_file);

  siglen = load_ticket(ticket_file,r,&myticket);

  load_known_hosts(kh_file,known_hosts);

  atexit(print_stats);

  start_capture(descr, (pcap_handler) process_packet);

  pcap_perror(descr,"Capture termiated");

  return(0);
}


