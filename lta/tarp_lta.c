/*  
   tarp_lta.c -- This program is used to generate TARP tickets

 
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
   Foundation, Inc., 51 Franklin Street, Fifth Floor, 
   Boston, MA 02110-1301,USA.

   This software is based on previous work done by ALoR. 
   However, it has been extensively modified by the Wesam Lootah.
   Please direct your comments and questions to:

   Wesam Lootah
   lootah@cse.psu.edu

   Note: This version of TARP is NOT suited for production environments.
   This version was developed for research purposes only.
*/

/*
 * Wesam Lootah
 *
 * Generate a tarp ticket
 *
 */

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define RSA_KEY_LEN 1024
#define RSA_EXPO 3
#define TICKET_LENGTH 30

#define MAGIC 0
#define TYPE 4
#define MAC 8
#define IP 14
#define TIMESTAMP 18
#define TIME_FROM 22
#define TIME_TO 26

int get_time() {
  int val;
  struct timeval t;              
  gettimeofday(&t, 0);           
  val = t.tv_sec;
  return val;
}

int raw_to_b64(char *r, int l, char **b)
{
   BIO *b64bio, *bio, *mbio;
   u_char *p; 
   int h;
   
   mbio = BIO_new(BIO_s_mem());
   b64bio = BIO_new(BIO_f_base64());
   bio = BIO_push(b64bio, mbio);
   BIO_write(bio, r, l);
   BIO_flush(bio);
   
   h = BIO_get_mem_data(mbio, &p);
  
   *b = (char *)strndup(p, h);

   BIO_free_all(bio);
   
   return h;
}

/*
 * convert a link layer address to a printable colon separated format
 */

char * ha_ntoa(const u_char *ll_addr)
{
   static char printable[18];

   sprintf(printable, "%02X:%02X:%02X:%02X:%02X:%02X", ll_addr[0], ll_addr[1],
                   ll_addr[2], ll_addr[3], ll_addr[4], ll_addr[5]);
   
   return printable;
}

/*
 * convert a link layer address from ascii to network
 */

char * str2mac(const char *ll_addr)
{
   static char network[6];
   int m1,m2,m3,m4,m5,m6;

   if (sscanf(ll_addr, "%02X:%02X:%02X:%02X:%02X:%02X", &m1, &m2, &m3, 
                           &m4, &m5, &m6) != 6)
      return NULL;
   
   network[0] = (char) m1;
   network[1] = (char) m2;
   network[2] = (char) m3;
   network[3] = (char) m4;
   network[4] = (char) m5;
   network[5] = (char) m6;
   
   return network;
}

/*
 * convert a ip address in dot notation to interger
 */

u_int32_t str2ip(const char *ip)
{
   return inet_addr(ip);
}

int main(int argc, char *argv[]) {

  RSA *r = NULL;
  unsigned char hash[20]; 
  FILE *key_file;
  unsigned int signlen;
  unsigned char *sign;
  char *sign_b64;
  char *data_b64;
  unsigned char *smac;
  u_int32_t  sip;
  int magic = 0x789a0102;
  int type  = 0xffff0000;
  int time_stamp, from_time, to_time;
  char *strdata;
  unsigned char data[TICKET_LENGTH] = {0x00};

  if (argc != 4) {
    printf("Usage %s <mac> <ip> <key_file>\n",argv[0]);
    exit(0);
  }

  if ((key_file = fopen(argv[3], "r")) == NULL) {
           fprintf(stderr, "Cannot open %s\n", argv[3]);
	   exit(0);
  }

  //printf("Start reading the private key\n");
  
  if ((r = PEM_read_RSAPrivateKey(key_file, NULL,0,NULL)) == NULL) {
    perror("Error reading private key\n");
    exit(0);
  }
  //printf("Read the private key\n");

  sign = malloc(RSA_size(r));
  //printf("Signing data\n");

  smac = (unsigned char *)str2mac(argv[1]);
  sip = str2ip(argv[2]);
  magic = htonl(magic);
  time_stamp = htonl(get_time());
  from_time = time_stamp;
  to_time = htonl(0x7fffffff);

  memcpy(data+MAGIC,&magic,4);  
  memcpy(data+TYPE,&type,4);
  memcpy(data+MAC,smac,6);
  memcpy(data+IP,&sip,4);
  memcpy(data+TIMESTAMP,&time_stamp,4);
  memcpy(data+TIME_FROM,&from_time,4);
  memcpy(data+TIME_TO,&to_time,4);
 
  /* create the ticket */
  /* sMAC, sIP, tMAC, tIP, magic, type, siglen, tstamp, tfrom, tto */
  
  if (!SHA(data, TICKET_LENGTH, hash)) {
    printf("Error hashing data\n");
    exit(0);
  }
  
  if (RSA_sign(NID_sha1, hash, 20, sign, &signlen, r) != 1) {
    printf("Error signing the data\n");
    exit(0);
  }
  raw_to_b64((char *)data,TICKET_LENGTH,&data_b64);
  raw_to_b64((char *)sign,signlen,&sign_b64);
  printf("%s\n%s\n",data_b64,sign_b64);
  exit(0);
}

