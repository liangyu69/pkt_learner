#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/types.h>
#include"modules/tcp.h"

int main() {
    int choice;
    char input[16];

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle=pcap_open_live("enp0s3",BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"打开网卡失败: %s\n",errbuf);
        return 1;
    }
    
    printf("\n================================\n");
    printf("   网络抓包学习工具\n");
    printf("================================\n\n");
    printf("1. TCP 学习\n");
    printf("2. 退出\n\n");
    
    while (1) {
        printf("请选择 (输入编号): ");
        fgets(input, sizeof(input), stdin);
        choice = atoi(input);
        
        if (choice == 1) {
            tcp_learn(handle);
            break;
        } else if (choice == 2) {
            printf("退出\n");
            break;
        } else {
            printf("无效选择\n");
        }
    }
    
    return 0;
}