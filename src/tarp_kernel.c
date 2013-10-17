/*  
   tarp_kernel.c -- functions to communicate with the
   TARP kernel module.
 
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

#include <fcntl.h>
#include <tarp_error.h>

<<<<<<< HEAD
//daveti: update the module path
//#define MODULE_PATH "/proc/sys/net/ipv4/tarp"
#define MODULE_PATH "/proc/tarp"
=======
#define MODULE_PATH "/proc/sys/net/ipv4/tarp"
>>>>>>> 2070764cfe7f940384d5dc874ae05ca320378614

void enable_kernel_arp(void);
void disable_kernel_arp(void);

void disable_kernel_arp(void) 
{
  int fd;

  //DEBUG_MSG("disable_kernel_Arp");
   
   if ((fd = open(MODULE_PATH, O_WRONLY)) == -1)
      ERROR_MSG("can't open proc file");

   if (write(fd, "1", 1) != 1)
      ERROR_MSG("can't enable tarp");

   close(fd);

   atexit(enable_kernel_arp);
}

void enable_kernel_arp(void)
{
   int fd;

   //DEBUG_MSG("enable_kernel_arp");
   
   if ((fd = open(MODULE_PATH, O_WRONLY)) == -1)
      ERROR_MSG("can't open proc file");

   if (write(fd, "0", 1) != 1)
      ERROR_MSG("can't disable tarp");

   close(fd);
}
