/*  
   tarp_crypto.c -- Tarp cryptographic routines.
 
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

#include "tarp_crypto.h"
#include <string.h>

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

/* ************************************************************************* 
 *                          init_crypto
 *************************************************************************** */
RSA * init_crypto(char *key_file_name) 
{
  RSA *r;
  FILE *key_file;

  if ((key_file = fopen(key_file_name, "r")) == NULL) {
    fprintf(stderr, "Cannot open %s\n", key_file_name);
    exit(0);
  }

  if ((r = PEM_read_RSAPublicKey(key_file, NULL,NULL,NULL)) == NULL) {
    perror("Error reading public key\n");
    exit(0);
  }

  if (!RSA_blinding_on(r,NULL)) {
    fprintf(stderr, "Error turning on RSA blinding\n");
    exit(0);
  }
  return r;
}

/* ************************************************************************* 
 *                          verify_signature
 *************************************************************************** */
int verify_signature(RSA *r, int siglen, unsigned char * ticket,int ticketlen)
{
  u_char hash[20];
  int c=0;

  if(!SHA(ticket,ticketlen, hash)) {
    printf("Error hashing data\n");
    exit(0);
  }
  
  c = RSA_verify(NID_sha1, hash, 20, ticket+ticketlen, siglen, r);
  return c;
}
/* ************************************************************************* 
 *                          load_ticket
 *************************************************************************** */
/* This function loads a ticket from a file
 * the function expects: 1- the name of the base64 encoded ticket file
 * 2- a pointer to the RSA object with the LTA public key
 * The ticket is loaded into the memory at *ticket_in
 */
int load_ticket(char *ticket_file_name, RSA *r, unsigned char **ticket_in) 
{
  FILE *ticket_file;
  int c,linelen = 400;
  int siglen_b64 = 256;
  int siglen;
  unsigned char *data, *ticket, *signature;
  char *signature_b64, *line;
  unsigned char hash[20]; 

  //open the ticket file
  if ((ticket_file = fopen(ticket_file_name, "r")) == NULL) {
    fprintf(stderr, "Cannot open %s\n", ticket_file_name);
    exit(0);
  }
  
  //alocate buffers
  line = malloc(linelen);
  signature_b64 = malloc(siglen_b64);

  //read first line which contains ticket data
  c = getline(&line,&linelen,ticket_file);
  b64_to_raw(line,&data);

  //read the signature
  int i=0;
  c = getline(&line,&linelen,ticket_file);
  while (c != -1) { //EOF check
    if (c != 1) {   //empty line
      //Note that the linefeed is also copied as it is needed to reconvert to raw data
      memcpy(signature_b64+i,line,c);
      i += c;
    }
     c = getline(&line,&linelen,ticket_file);
  }
  signature_b64[i]='\0';
  siglen = b64_to_raw(signature_b64,&signature);

  //we know the signature length, now we can allocate the ticket buffer
  ticket = malloc(TICKET_LEN+siglen);
  memcpy(ticket,data,TICKET_LEN);
  memcpy(ticket+TICKET_LEN,signature,siglen);
 
  //verify ticket
  if(!SHA(ticket,TICKET_LEN, hash)) {
    printf("Error hashing data\n");
    exit(0);
  }
  
  if ((c = RSA_verify(NID_sha1, hash, 20, ticket+TICKET_LEN, siglen, r)) != 1) {
    printf("Signature is NOT valid %d\n",c);
  }
  else {
     printf("Signature is valid\n");
  }
  free(data);
  free(line);
  free(signature_b64);
  free(signature);
  *ticket_in = ticket;
  return siglen;
}
