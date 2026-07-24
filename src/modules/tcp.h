#ifndef TCP_H
#define TCP_H

#include <pcap.h>


typedef struct my_tcphdr{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t doff_res;
    uint8_t flags;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urg_ptr;
}mytcp;

// 声明TCP学习函数
void tcp_learn(pcap_t *handle);

#endif