/*  
   tarp_hosts.h -- header file for interoperation with ARP
 
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
 * tarp_hosts.h -- Header file for tarp_hosts.c
 * 
 * This module defines functions to interoperate with ARP
 *
 * Author: Wesam Lootah
 *
 */

#define KH_MAX_RANGES 10

struct ip_range {
  u_int32_t from;
  u_int32_t to;
};

/* ************************************************************************* 
 *                          load_known_hosts
 *************************************************************************** */
void load_known_hosts(char * kh_file_name, struct ip_range *kh);

/* ************************************************************************* 
 *                          is_known_host
 *************************************************************************** */
int is_known_host(u_int32_t ip_in, struct ip_range *kh) ;
