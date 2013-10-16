/*  
   tarp_error.h -- Error handling header file
 
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

#if !defined(TARP_SYSLOG_H)
#define TARP_SYSLOG_H

extern void syslog_msg(char *message, ...);

#endif

#if !defined(TARP_ERROR_H)
#define TARP_ERROR_H


#include <errno.h>

extern void error_msg(char *file, int line, char *message, ...);

#define ERROR_MSG(x, args...) error_msg(__FILE__, __LINE__, x, ## args)

#define ON_ERROR(x, fmt, args...) do { if (x == NULL) ERROR_MSG(fmt, ## args); } while(0)

#endif

#ifdef DEBUG
#define DEBUG_MSG(fmt, args...)			\
  fprintf(stderr, fmt, ## args)
#else
#define DEBUG_MSG(fmt, ...)
#endif

#ifdef DEBUG_LEVEL2
#define DEBUG_MSG2(fmt, ...)			\
  fprintf(stderr, fmt, __VA_ARGS__)
#else
#define DEBUG_MSG2(fmt, ...)
#endif

#ifdef DEBUG_LEVEL3
#define DEBUG_MSG3(fmt, args...)			\
  fprintf(stderr, fmt, ## args)
#else
#define DEBUG_MSG3(fmt, ...)
#endif


