/*  
   tarp_hosts.c -- This file defines fuctions to interoperate with
   ARP.
 
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

/*
 * 
 * Known Hosts are trusted hosts that do not run TARP. 
 * TARP will accept classic ARP replies from known hosts
 * Note that ARP entries for known hosts are not protected by TARP 
 * and therefore can be poisoned.
 *
 */

#include <arpa/inet.h>
#include <tarp_hosts.h>
#include <stdio.h>
#include <string.h>
#include <tarp_error.h>
#include <stdlib.h>

/* ************************************************************************* 
 *                          load_known_hosts
 *************************************************************************** */
void load_known_hosts(char * kh_file_name, struct ip_range *kh) 
{
  FILE * kh_file;
  char * line;
  int linelen=400;
  int i;
  char ipfrom[16];
  char ipto[16];
  int c;

  //open the known hosts file
  if ((kh_file = fopen(kh_file_name, "r")) == NULL) {
    ERROR_MSG("Cannot open %s\n", kh_file_name);
    exit(0);
  }
  
  //alocate buffers
  line = malloc(linelen);
 
  DEBUG_MSG3("Loading known hosts\n");
  for(i=0; i<KH_MAX_RANGES; i++) {
    if ((c = getline(&line,&linelen,kh_file)) == -1) {
      break;
    }
    if (sscanf(line,"%s %s",ipfrom,ipto) != 2) {
      ERROR_MSG("Error reading known hosts file\n");
    }
    kh[i].from = htonl(str2ip(ipfrom));
    kh[i].to = htonl(str2ip(ipto));
    DEBUG_MSG3("Known host: %s to ",ip2str(ntohl(kh[i].from)));
    DEBUG_MSG3("%s\n",ip2str(ntohl(kh[i].to))); 
  }
}
/* ************************************************************************* 
 *                          is_known_host
 *************************************************************************** */
int is_known_host(u_int32_t ip_in, struct ip_range *kh) 
{
  u_int32_t ip;
  ip = ntohl(ip_in);
  int i;
  for(i=0; i<KH_MAX_RANGES; ++i) {
    if ((ip >= kh[i].from) && (ip <= kh[i].to)) {
      return 1;
    }
  }
  return 0;
}
