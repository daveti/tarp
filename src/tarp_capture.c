/*  
   tarp_capture.c -- Tarp packet capture routines.
 
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


#include <pcap.h>

#define PCAP_IFACE "any"
#define PCAP_FILTER "arp"
#define PCAP_PROMISC_FALSE 0
#define PCAP_TIMEOUT 0
#define PCAP_OPTIMIZE 1 
#define PCAP_BUFSIZ 1550


/*
 *  init_capture 
 *  initializes the capture library (pcap). return a device and descriptor 
 *  that can be used to capture packets, all parameters are updated by the fucnction.
 */
pcap_t * init_capture() {

  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error buffer */
  char *dev;
  pcap_t *descr;
  struct bpf_program bpf_prog;          

 
  /* Open the device for capture*/
  descr = pcap_open_live(PCAP_IFACE, PCAP_BUFSIZ, PCAP_PROMISC_FALSE, PCAP_TIMEOUT, errbuf);
  if (descr == NULL) {
    error_msg(errbuf);
  }

  if (pcap_lookupnet(PCAP_IFACE, &netp, &maskp, errbuf) == -1) {
    error_msg(errbuf);
  }

  if (pcap_compile(descr, &bpf_prog, PCAP_FILTER, PCAP_OPTIMIZE, netp) == -1) {
    error_msg("pcap_compile error\n");
  }

  if (pcap_setfilter(descr, &bpf_prog) == -1) {
    error_msg("pcap_setfilter error\n");
  }

  return descr;

}

void close_capture(pcap_t *descr) {

  pcap_close(descr);
   
}

void start_capture(pcap_t *descr, pcap_handler process_packet) {

  pcap_loop(descr, -1, process_packet, NULL);

}
