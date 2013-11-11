/*  
   tarp_genkeys.c -- This program is used to generate private/public
   key pairs for use in TARP.
 
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

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

//daveti: timing for key gen
#include <sys/time.h>

//#define RSA_KEY_LEN 1024
#define RSA_EXPONENT 3
#define RSA_CALLBACK NULL
#define RSA_CB_ARGS NULL

int main(int argc,char *argv[]) {

  RSA *r = NULL;
  FILE *priv_output_file;
  FILE *pub_output_file;
  int key_len;
  char *priv_file_name;
  char *pub_file_name;

  char priv_suffix[] = "_priv.txt";
  char pub_suffix[] = "_pub.txt";
  int len;

  if (argc != 4) {
    printf("Usage %s <key_file> <keylen> <password protect flag>\n",argv[0]);
    exit(0);
  }
  
  priv_file_name = malloc(40);
  pub_file_name = malloc(40);
  len = strlen(argv[1]);
  memcpy(priv_file_name, argv[1], len);
  memcpy(pub_file_name, argv[1], len);
  memcpy(priv_file_name+len, priv_suffix, 10);
  memcpy(pub_file_name+len, pub_suffix, 9);

  printf("%s %s\n",priv_file_name,pub_file_name);

  key_len = atoi(argv[2]);

//daveti: add time measurement for this function call
struct timeval tpstart,tpend;
float timeuse = 0;
gettimeofday(&tpstart,NULL);

  r = RSA_generate_key(key_len, RSA_EXPONENT, RSA_CALLBACK, RSA_CB_ARGS);

gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
printf("Total time on crypto_genkeypair() is [%f] ms\n", timeuse);
  
  if ((priv_output_file = fopen(priv_file_name, "w")) == NULL)
           fprintf(stderr, "Cannot open %s\n", argv[1]);
    
  if ((pub_output_file = fopen(pub_file_name, "w")) == NULL)
           fprintf(stderr, "Cannot open %s\n", argv[1]);

  if (strcmp(argv[3],"0")==0) {
    if (PEM_write_RSAPrivateKey(priv_output_file,r,EVP_des_ede3_cbc(),NULL,0,NULL,NULL) != 1) {
      printf("Error writing the private key\n");
    }
  }
  else {
     if (PEM_write_RSAPrivateKey(priv_output_file,r,NULL,NULL,0,NULL,NULL) != 1) {
       printf("Error writing the private key\n");
     }
  }
  if (PEM_write_RSAPublicKey(pub_output_file,r) != 1) {
    printf("Error writing the public key\n");
  }
  close(priv_output_file);
  close(pub_output_file);
  exit(0);
}
