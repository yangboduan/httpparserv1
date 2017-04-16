#include <string.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include "formatdatetime.h"
#include "regexhttpparser.h"
using namespace std;
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{ 
    struct in_addr addr;//用来表示一个32位的IPv4地址的结构体,源
    struct ether_header *ethernet_hdrptr; //以太网头部 
    unsigned short ethernet_type;           //二层头部的以太网类型 
    struct iphdr *iphdrptr;  //IP头部结构体 
    struct tcphdr *tcphdrptr;//TCP头部结构体 
    struct ether_arp *arp__packet;
    char buffer[ETH_FRAME_LEN];//以太网正的最大长度
    char *data; 
    int * id = (int *)arg; 
    int ipheardlen,tcpheardlen;
    int maciptcpheardlen;//2-4层报文头部总长度 
    unsigned char *mac_string;
    cout <<formatdatetime()<<"  "; 
    ethernet_hdrptr = (struct ether_header *)packet;
   
    //printf("id: %d\n", ++(*id));  //抓包计数
    //printf("Packet length: %d\n", pkthdr->len);  
    //printf("Number of bytes: %d\n", pkthdr->caplen);
  
    //分析二层头部信息 
    ethernet_type = ntohs(ethernet_hdrptr->ether_type);//获得以太网的类型
  
    //分析数据包二层头部，解析出上层协议
    if (ethernet_type == ETHERTYPE_IP){ //IP protocol
        const char *ipsrcaddrstr = NULL; 
        const char *ipdstaddrstr = NULL; 

        //三层头部信息
        iphdrptr = (struct iphdr*)    (packet+sizeof(struct ether_header));//得到ip包头
	addr.s_addr = iphdrptr->saddr;//源IP地址
	cout <<iphdrptr->saddr<<" ddddddd";
	cout<<iphdrptr->daddr<<" dddd";
        ipsrcaddrstr = inet_ntoa(addr);
        addr.s_addr = iphdrptr->daddr;//目的IP地址
        ipdstaddrstr = inet_ntoa(addr);
	cout <<"src_ip:"<<ipsrcaddrstr<<"\t"<<"dst_ip:"<<ipdstaddrstr<<endl;	


        ipheardlen = (iphdrptr->ihl)*4;//IP头部长度
    
            //四层头部信息
        tcphdrptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));//得到tcp包头
        tcpheardlen = tcphdrptr->doff*4;//TCP头部长度
    
        maciptcpheardlen = (iphdrptr->ihl)*4 + tcphdrptr->doff*4 + 14;//2-4层头部的总长度
    
        //cout <<inet_ntoa(ipsrcaddr)<<":"<<ntohs(tcphdrptr->source)<<" ----> "<<inet_ntoa(ipdstaddr)<<":"<<ntohs(tcphdrptr->dest)<<" [SYN:"<<tcphdrptr->syn<<"; ACK:"<<tcphdrptr->ack<<"]"<<endl;
/*TCP 报文头部字段值
            <<"  seq:"<<tcphdrptr->seq
	<<"  ack_seq:"<<tcphdrptr->ack_seq
	<<"  syn:"<<tcphdrptr->syn
	<<"  fin:"<<tcphdrptr->fin
                <<"  ack:"<<tcphdrptr->ack
	cout<<" ]";
*/
    }
   data = (char*)(packet+maciptcpheardlen);//得到TCP报文内容
    onMessageBegin(data);
    onMessagehost(data);
    //usleep(800*1000);
//去掉该注释，显示报文详细内容 
    int i;  
    cout<<data;
    cout<<"TCPContentLen:"<<(pkthdr->caplen-maciptcpheardlen)<<endl; 
    printf("\n\n"); 

}  
  

