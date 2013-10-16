/*  
   tarp_error.c -- Tarp error handling.
 
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


#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <tarp_error.h>

#define SYSLOG_MSG_LEN 500

#define ERROR_MSG_LEN 200

void syslog_msg(char *message, ...);

void error_msg(char *file, int line, char *message, ...);

/*******************************************/

void error_msg(char *file, int line, char *message, ...)
{
   va_list ap;
   char errmsg[ERROR_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(errmsg, ERROR_MSG_LEN, message, ap);
   va_end(ap);

   DEBUG_MSG("ERROR : [%s:%d] %s | ERRNO %d | %s", file,
                   line, errmsg, errno, strerror(errno));
   

   fprintf(stderr, "ERROR : [%s:%d] %s | ERRNO %d | %s\n", file,
                            line, errmsg, errno, strerror(errno));
   
   syslog_msg("[%s:%d]\n\n %s \n\n ERRNO %d | %s \n\n", file,
                   line, errmsg, errno, strerror(errno));
   exit(-1);
}

/*******************************************/

void syslog_msg(char *message, ...)
{
   va_list ap;
   char logmsg[SYSLOG_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(logmsg, SYSLOG_MSG_LEN, message, ap);
   va_end(ap);

/* XXX - fix this */   
   //fprintf(stderr, "SYSLOG : %s\n", logmsg);

   syslog(LOG_DAEMON | LOG_PID | LOG_NOTICE, logmsg);

}

