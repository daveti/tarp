void init_cache();
unsigned char * find_ticket(int ip);
void cache_ticket(int ip, unsigned char *ticket);
int compare_tickets(unsigned char *t1, unsigned char *t2);      
int compare_timestamp(int ip, unsigned char *ticket);
