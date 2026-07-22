#include <stdio.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include<netinet/if_ether.h>
#include"tcp.h"

// TCP打印函数（你的原始代码）
void packet_handler(__u_char*args,const struct pcap_pkthdr*header,const __u_char*packet){
    // 1. 跳过 14 字节的以太网帧头，指向 IP 头的起始位置
    struct iphdr *ip = (struct iphdr *)(packet + 14);

    char src_ip[16], dst_ip[16];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, sizeof(dst_ip));

    if (ip->protocol != 6) return;

    
    unsigned int ip_header_len=ip->ihl*4;
    // 2. 定位 TCP 头起始位置（跳过 IP 头）
    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
    
    // 3. 从 TCP 头里读出序列号和确认号（注意：都是网络序，要转主机序）
    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_seq = ntohl(tcp->ack_seq);

    // 4. 判断标志位
    int is_syn = tcp->syn;
    int is_ack = tcp->ack;
    int is_fin = tcp->fin;
    
    
    // 6. 打印完整信息
    printf("TCP: %s:%d -> %s:%d, Seq=%u, Ack=%u, SYN=%d, ACK=%d, FIN=%d\n",
       src_ip, src_port, dst_ip, dst_port, seq, ack_seq, is_syn, is_ack, is_fin);
}

// TCP学习入口函数
void tcp_learn(pcap_t*handle) {
     // 1. 定义过滤规则字符串
    char filter_exp[] = "tcp";   

    // 2. 声明一个 bpf_program 结构体（存放编译后的过滤指令）
    struct bpf_program filter;

    // 3. 编译并应用过滤器
    if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "编译过滤器失败: %s\n", pcap_geterr(handle));
        return ;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "应用过滤器失败: %s\n", pcap_geterr(handle));
        return ;
    }
    
    printf("开始抓包（按 Ctrl+C 停止）...\n");
    pcap_loop(handle,-1,packet_handler,NULL);

    pcap_close(handle);
}