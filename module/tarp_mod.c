/*  
   tarp_mod.c -- This module is used to enable/disable kernel ARP processing.
 
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

----------------------------------------------------------------

NOTE: we are no longer to create a proc entry just using create_proc_entry
with the dir directly, like "/proc/sys/net/ipv4/tarp", though we could still
create a proc entry just under "/proc". Anyway, my point is we will try to
add the proc entry just under "/proc" to avoid the effort!
Oct 15, 2013
root@davejingtian.org
http://davejingtian.org

*/


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/netdevice.h>  /* dev_[add|remove]_pack */
// daveti: add name space for 

#define MODULE_NAME    "tarp_mod"
#define TARP_VERSION "0.01"
MODULE_AUTHOR("Wesam Lootah");
MODULE_DESCRIPTION("Ticket-based ARP");
// daveti: add license here
MODULE_LICENSE("GPL");

#define MODULE_PATH "sys/net/ipv4/tarp"

// daveti: use parent dir and file name
#define MODULE_PATH_DIR "/proc/sys/net/ipv4"
#define MODULE_FILE_NAME "tarp"

/* 
 * this structure is declared in net/ipv4/arp.c 
 * we need its address.
 * so Makefile greps the /boot/System.map searching for it
 * then it pass the value in the ARP_PACKET_TYPE_ADDR
 */

struct packet_type *arp_packet_type = (void *) ARP_PACKET_TYPE_ADDR;


/* Global */
int enabled = 0;
// daveti: add proc dir parent for tarp
struct proc_dir_entry *parent;

/* *********************************************************************** */

void enable_tarp(void)
{
   dev_remove_pack(arp_packet_type);

   printk(KERN_INFO "[tarp] enabled\n");
   printk(KERN_INFO "[tarp] kernel can now receive ARP entries "\
                          "only through TARP daemon\n");
}

void disable_tarp(void)
{      
   dev_add_pack(arp_packet_type);
         
   printk(KERN_INFO "[tarp] disabled\n");
   printk(KERN_INFO "[tarp] kernel can now receive \"classic\" "\
                          "ARP packets\n");
}

/* *********************************************************************** */
int proc_read (char *buf, char **start, off_t offs, int len) 
{  
   int written;
   
   //  MOD_INC_USE_COUNT;
   
   written = sprintf(buf, "%d\n", enabled);

   // MOD_DEC_USE_COUNT;
   
   return written;
}

ssize_t proc_write( struct file *file, const char *buf, size_t length, loff_t *offset)
{
   #define MESSAGE_LEN 5
   int i, value;
   char *message;

   //   MOD_INC_USE_COUNT;

   message = kmalloc(MESSAGE_LEN, GFP_KERNEL);

   for (i = 0; i < MESSAGE_LEN-1 && i < length; i++)
      get_user(message[i], buf + i);
   
   message[i]='\0';
   value = simple_strtoul(message, NULL, 10);
   kfree(message);
 
   switch(value) {
      case 1:   /* enable it */
         if (enabled) {
	   //       MOD_DEC_USE_COUNT;
            return i;
         }
         
         enable_tarp();      
	 enabled = 1;
         
         break;
      case 0:   /* disable it */
         if (!enabled) {
	   //  MOD_DEC_USE_COUNT;
            return i;
         }
   
         disable_tarp();
	 enabled = 0;
         
         break;
      default:  /* error */
	//MOD_DEC_USE_COUNT;
         return -1;
         break;
   }
  
   // MOD_DEC_USE_COUNT;
  
   return i;                                                
}

/* ******************************************************************* */
static int tarp_init(void)
{
  struct proc_dir_entry *mod_entry;
 
  // daveti: below will cause kernel Oops...as the the usage
  // of create_proc_entry is not right!
  // mod_entry = create_proc_entry(MODULE_PATH, 0644, NULL);
/*
NOT WORK!
  struct file *fp = filp_open(MODULE_PATH_DIR, O_RDONLY, 0);
  parent = PDE(fp->f_dentry->d_inode);
  filp_close(fp, NULL);
  if (parent == NULL)
  {
	printk(KERN_INFO "Get proc dir entry [%s] failure\n", MODULE_PATH_DIR);
	return -1;
  }
  mod_entry = create_proc_entry(MODULE_FILE_NAME, 0644, parent);
*/
  mod_entry = create_proc_entry(MODULE_FILE_NAME, 0644, NULL);
  // daveti: no owner in kernel 3.2.0.55
  // mod_entry->owner = THIS_MODULE;
  if (mod_entry == NULL)
  {
	printk(KERN_INFO "tarp_mod init failure\n");
	return -1;
  }
  mod_entry->read_proc = (read_proc_t *)&proc_read;
  mod_entry->write_proc = (write_proc_t *)&proc_write;
  printk(KERN_INFO "%s module loaded\n", MODULE_NAME);
  // daveti: check the arp_packet_type
  printk(KERN_INFO "arp_packet_type [%p]\n", arp_packet_type);
  return 0;
}

static void tarp_exit(void)
{ 
  // daveti: need to update this too...
  // remove_proc_entry(MODULE_PATH, NULL);
  remove_proc_entry(MODULE_FILE_NAME, NULL);
  // remove_proc_entry(MODULE_FILE_NAME, parent);

  if (enabled){
    disable_tarp();
    }
  printk(KERN_INFO "%s removed\n", MODULE_NAME);
}
/* *********************************************************************** */

module_init(tarp_init);
module_exit(tarp_exit);

/* ******************************************************************* */
