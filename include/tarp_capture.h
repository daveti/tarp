pcap_t * init_capture();

void close_capture(pcap_t *descr);

void start_capture(pcap_t *descr, pcap_handler process_packet);
