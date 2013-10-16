/*
 * Wesam Lootah
 *
 * Generate a tarp ticket
 *
 */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <sys/time.h>
#include <libnet.h>

#include <tarp_net.h>
#include <wl_time.h>

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

#define ARPOP_D_REPLY 5

int get_time() {
  int val;
  struct timeval t;              
  gettimeofday(&t, 0);           
  val = t.tv_sec;
  return val;
}


int main(int argc, char *argv[]) {

  RSA *r = NULL;
  unsigned char hash[20]; 
  FILE *key_file;
  int signlen;
  char *sign;
  char *sign_b64;
  char *data_b64;
  unsigned char * smac;
  unsigned char * dmac;
  u_int32_t  sip, dip;
  int magic = 0x789a0102;
  int type  = 0xffff0000;
  int time_stamp, from_time, to_time;
  char *strdata;
  unsigned char data[TICKET_LENGTH] = {0x00};
  short arp_opcode = ARPOP_D_REPLY;

  int c;
  libnet_t *l;
  libnet_ptag_t t;
  char *device = NULL;
  u_int8_t *packet;
  u_int32_t packet_s;
  char errbuf[LIBNET_ERRBUF_SIZE];
  char * payload;
  int paylen;
  int ret;

  struct fixed_ether_arp arp_packet;

 
  //Check number of command line arguments
  if (argc != 5) {
    printf("Usage %s <device> <mac> <ip> <key_file>\n",argv[0]);
    exit(0);
  }

  //Open RSA private key file and load it
  if ((key_file = fopen(argv[4], "r")) == NULL) {
    fprintf(stderr, "Cannot open %s\n", argv[4]);
    exit(0);
  }
  
  if ((r = PEM_read_RSAPrivateKey(key_file, NULL,0,NULL)) == NULL) {
    perror("Error reading private key\n");
    exit(0);
  }
  
  device = argv[1];
  l = init_packet_injection(device,errbuf);
  
  if (l == NULL) {
    fprintf(stderr, "%s", errbuf);
    exit(EXIT_FAILURE);
  }

  smac = get_mac(l);
  sip = get_ip(l);

  //Allocate memory for the signature
  sign = malloc(RSA_size(r));

  //printf("Debug 01\n");  
  if ((dmac = str2mac(argv[2])) == NULL) {
    printf("Invalid source mac address\n");
    exit(0);
  }

  //printf("Debug 02\n");
  dip = str2ip(argv[3]);
  magic = htonl(magic);
  //time_stamp = htonl(get_time());
  time_stamp = htonl(0x44183307);
  from_time = time_stamp;
  to_time = htonl(0x7fffffff);

  //printf("Debug 03\n");
  memcpy(data+MAGIC,&magic,4);  
  memcpy(data+TYPE,&type,4);
  memcpy(data+MAC,dmac,6);

  printf("Debug 04\n");

  memcpy(data+IP,&dip,4);
  memcpy(data+TIMESTAMP,&time_stamp,4);
  memcpy(data+TIME_FROM,&from_time,4);
  memcpy(data+TIME_TO,&to_time,4);
  
  if (!SHA(data, TICKET_LENGTH, hash)) {
    printf("Error hashing data\n");
    exit(0);
  }
  
  if (RSA_sign(NID_sha1, hash, 20, sign, &signlen, r) != 1) {
    printf("Error signing the data\n");
    exit(0);
  }

  paylen = signlen+TICKET_LENGTH;
  payload = malloc(paylen);
  memcpy(payload,data,TICKET_LENGTH);
  memcpy(payload+TICKET_LENGTH,sign,signlen);


  /* ************************************************** */
  //Initialize packet injection using libnet
  /* ************************************************** */
  /*
    device = argv[1];
    l = init_packet_injection(device,errbuf);
 
    if (l == NULL) {
      fprintf(stderr, "%s", errbuf);
      exit(EXIT_FAILURE);
    }
  */

  arp_packet.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arp_packet.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
  arp_packet.ea_hdr.ar_hln = 6;
  arp_packet.ea_hdr.ar_pln = 4;
  arp_packet.ea_hdr.ar_op = htons(arp_opcode);
  
  memcpy(arp_packet.arp_sha,smac,6);      
  memcpy(arp_packet.arp_tha, dmac,6);
  memcpy(arp_packet.arp_spa, &sip, 4); 
  memcpy(arp_packet.arp_tpa, &dip, 4); 

  send_arp_packet(l,(struct libnet_arp_hdr *)&arp_packet,payload,paylen);

  libnet_destroy(l);
  /* ************************************************** */

  ret =  verify_signature(r, signlen, payload, TICKET_LENGTH);

  if (ret != 1) {
    printf("Signature is not valid\n");
  }
  else
    {
      printf("Signature is valid\n");
    }
  printf("Packet sent\n");
  return (EXIT_SUCCESS);
  
  exit(0);
}

