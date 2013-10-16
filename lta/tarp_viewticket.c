/*  
   tarp_viewticket.c -- This program is used view ticket details

 
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

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define TICKET_DATA_LENGTH 30
#define MAGIC 0
#define TYPE 4
#define MAC 8
#define IP 14
#define TIMESTAMP 18
#define TIME_FROM 22
#define TIME_TO 26

int b64_to_raw(char *b, u_char **r)
{
   BIO *b64bio, *bio, *mbio;
   int len;
   int raw_len;

   /*
    * base64 encodes 6 bit per char, so if we have
    * the len of the base64 we can copute the raw
    * lan as folow:
    *    b64_len * 6 = number of bits
    *    n_bits / 8 = number of bytes
    *    
    * 6/8 == 3/4
    * 
    */
   
   raw_len = strlen(b) * 3 / 4 + 8;
   
   *r = calloc(1, raw_len);
   
   mbio = BIO_new_mem_buf(b, strlen(b));
   b64bio = BIO_new(BIO_f_base64());
   bio = BIO_push(b64bio, mbio);
   
   len = BIO_read(bio, *r, raw_len);
   
   BIO_free_all(bio);

   return len;
}

char * ip2str(const u_char *ip)
{
   return inet_ntoa(*(struct in_addr *)ip);
}

main(int argc, char *argv[]) {

  FILE *ticket_file, *key_file;
  int linelen = 400;
  char *line;
  int c;

  u_char *data;
  unsigned char *ticket;

  time_t time1;

  char *signature_b64;
  u_char *signature;

  RSA *r;
  unsigned char hash[20]; 
  int signlen;

  if (argc != 3) {
    printf("Usage %s <ticket_file> <public_key_file>\n",argv[0]);
    exit(0);
  }
  line = malloc(linelen);
  ticket = malloc(TICKET_DATA_LENGTH);
  signature_b64 = malloc(256);

  /* open the ticket file */
  if ((ticket_file = fopen(argv[1], "r")) == NULL) {
    fprintf(stderr, "Cannot open %s\n", argv[1]);
    exit(0);
  }
  c = getline(&line,&linelen,ticket_file);
  b64_to_raw(line,&data);
  memcpy(ticket,data,TICKET_DATA_LENGTH);

  //Print  MAGIC
  printf("MAGIC: ");
  printf("%02X:%02X:%02X:%02X\n", ticket[MAGIC+0], ticket[MAGIC+1], ticket[MAGIC+2], ticket[MAGIC+3]);
  //Print TYPE and Signature Length
  printf(" TYPE: ");
  printf("%02X:%02X:%02X:%02X\n", ticket[TYPE+0], ticket[TYPE+1], ticket[TYPE+2], ticket[TYPE+3]);
  //Print MAC address 
  printf("  MAC: ");
  printf("%02X:%02X:%02X:%02X:%02X:%02X\n", ticket[MAC+0], ticket[MAC+1], ticket[MAC+2], ticket[MAC+3], \
	 ticket[MAC+4], ticket[MAC+5]);
  //Print IP address
  printf("   IP: ");
  printf("%s\n",ip2str(ticket+IP));
  //Print Issue Timestamp
  printf("STAMP: ");
  time1 = ntohl(*((int *)(&ticket[TIMESTAMP])));
  printf("%s", ctime(&time1));
  //Print From time
  printf(" FROM: ");
  time1 = ntohl(*((int *)(&ticket[TIME_FROM])));
  printf("%s", ctime(&time1));
  //Print Expiration time
  printf("  EXP: ");
  time1 = ntohl(*((int *)(&ticket[TIME_TO])));
  printf("%s", ctime(&time1));
  
  //Read the signature
  int i=0;
  c = getline(&line,&linelen,ticket_file);
  while (c != -1) {
    if (c != 1) {
      memcpy(signature_b64+i,line,c);
      i += c;
    }
     c = getline(&line,&linelen,ticket_file);
  }
  //printf("%s",signature_b64);

  signlen = b64_to_raw(signature_b64,&signature);

  //for(i=0; i<signlen; ++i) {
  //  printf("%02X ", signature[i]);
  //}
  //printf("\n");

  if ((key_file = fopen(argv[2], "r")) == NULL)
    fprintf(stderr, "Cannot open %s\n", argv[1]);
  
  if ((r = PEM_read_RSAPublicKey(key_file, NULL,NULL,NULL)) == NULL) {
    perror("Error reading public key\n");
    exit(0);
  }

  if (!RSA_blinding_on(r,NULL)) {
    printf("Error turning on RSA blinding\n");
    exit(0);
  }
  if(!SHA(ticket,TICKET_DATA_LENGTH, hash)) {
    printf("Error hashing data\n");
    exit(0);
  }
  
  if ((c = RSA_verify(NID_sha1, hash, 20, signature, signlen, r)) != 1) {
    printf("************ Signature is NOT valid %d ***********\n",c);
  }
  else {
     printf("************ Signature is valid **************\n");
  }

}
