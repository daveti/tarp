/*  
   tarp_ticket.c -- Ticket caching
 
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

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#define TABLE_SIZE 256
#define ENTRY_SIZE 168

struct cache_entry {
  int valid;
  u_char *entry;
};

struct cache_entry c_tickets[TABLE_SIZE];

init_cache() {
  int i=0;
  for(i=0;i<TABLE_SIZE;++i) {
    c_tickets[i].valid = 0;
    c_tickets[i].entry = NULL;
  }
}


unsigned char * find_ticket(int ip) 
{
  int index;
  unsigned char *ret = NULL;

  /* left most bit is the least significant bit */
  index = (ip >> 24) && (0x000000ff);

  if (c_tickets[index].entry != NULL) {
    ret = c_tickets[index].entry;
  }
  
  return ret;
}

void cache_ticket(int ip, unsigned char *ticket) {
  int index;

  /* left most bit is the least significant bit */
  index = (ip >> 24) && (0x000000ff);
  if (c_tickets[index].entry == NULL) {
    c_tickets[index].entry = malloc(ENTRY_SIZE);
  }
  memcpy(c_tickets[index].entry,ticket,ENTRY_SIZE);
}

int compare_tickets(unsigned char *t1, unsigned char *t2) {
  /* assume that the tickets are of length divisable by 4 */
  /* use integer comparison */
  int i=0;
  int match = 1;

  for(i=0; i<ENTRY_SIZE/4; ++i) {
    if (*(t1+i) != *(t2+i)) {
      match = 0;
      break;
    }
  }
  return match;
}
    
int compare_timestamp(int ip, unsigned char *ticket)
/* return 1 if the passed ticket has a newer timestamp than the 
 * cached entry 
 */
{
  int index;
  int t1;
  int t2;

  /* left most bit is the least significant bit */
  index = (ip >> 24) && (0x000000ff);

  #define TIMESTAMP_OFFSET 28

  t1 = ntohl(*(int *)ticket+TIMESTAMP_OFFSET);
  t2 = ntohl (*(int *)(c_tickets[index].entry)+TIMESTAMP_OFFSET);

  if (t1 > t2)
    return 1;
  else if (t1 == t2)
    return 0;
  else 
    return -1;
  
}

