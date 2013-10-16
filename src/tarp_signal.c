/*  
   tarp_signal.c -- Signal handling
 
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

#include <signal.h>
#include <sys/resource.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <tarp_error.h>

#define RUNNING_DIR	"/tmp"
#define LOCK_FILE	"/tmp/tarpd.lock"

void handle_signals(void);
void daemonize(void);

void signal_SEGV(int sig)
{
   
   /* restore the kernel */
   enable_kernel_arp();
   
   printf("Seg fault\n");
   syslog_msg("TARP: Ooops ! This shouldn't happen...");
   syslog_msg("TARP: Segmentation fault !");
   exit(1);
}

void signal_TERM(int sig)
{
  fprintf(stderr, "\n\n Shutting down (received SIGNAL: %d)\n\n", sig);
  signal(sig, SIG_IGN);
  exit(1);
}

void handle_signals() 
{
  signal(SIGINT,   signal_TERM);
  signal(SIGHUP,   signal_TERM);
  signal(SIGTERM,  signal_TERM);
  signal(SIGPIPE,  signal_TERM);
  signal(SIGSEGV,  signal_SEGV);
}

/*************************************/
/* 
 * daemonize the program
 */
void daemonize()
{
int i,lfp;
char str[10];
	if(getppid()==1) return; /* already a daemon */
	i=fork();
	if (i<0) exit(1); /* fork error */
	if (i>0) exit(0); /* parent exits */
	/* child (daemon) continues */
	setsid(); /* obtain a new process group */
	for (i=getdtablesize();i>=0;--i) close(i); /* close all descriptors */
	i=open("/dev/null",O_RDWR); dup(i); dup(i); /* handle standart I/O */
	umask(027); /* set newly created file permissions */
	//following line commented because it meant the commandline argument for key files
	//had to specify a non-relative path
	//chdir(RUNNING_DIR); /* change running directory */
	lfp=open(LOCK_FILE,O_RDWR|O_CREAT,0640);
	if (lfp<0) exit(1); /* can not open */
	if (lockf(lfp,F_TLOCK,0)<0) exit(0); /* can not lock */
	/* first instance continues */
	sprintf(str,"%d\n",getpid());
	write(lfp,str,strlen(str)); /* record pid to lockfile */
	signal(SIGCHLD,SIG_IGN); /* ignore child */
	signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
}

void daemonize_old(void)
{
   int pid;

   // DEBUG_MSG("daemonize");

   //#ifdef DEBUG
   /* in debug mode don't demonize.... */
   //return;
   //#endif
   
   if((signal(SIGTTOU, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal(SIGTTOU)");

   if((signal(SIGTTIN, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal(SIGTTIN)");

   if((signal(SIGTSTP, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal(SIGTSTP)");

   if((pid = fork()) < 0)
      ERROR_MSG("fork() during daemonization");
   else if(pid != 0) {
      fprintf(stdout, "sarpd demonized with PID: %d", pid);
      exit(0);
   }

   /* here is the daemon */

   if(setsid() == -1)
      ERROR_MSG("setsid()");

   close(fileno(stdin));
   close(fileno(stdout));
        
}



/* EOF */

// vim:ts=3:expandtab

