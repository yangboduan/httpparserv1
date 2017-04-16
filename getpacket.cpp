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
    ethernet_hdrptr = (struct ether_header *)packet;
   
    //printf("id: %d\n", ++(*id));  //抓包计数
    //printf("Packet length: %d\n", pkthdr->len);  
    //printf("Number of bytes: %d\n", pkthdr->caplen);
  
    //分析二层头部信息 
    ethernet_type = ntohs(ethernet_hdrptr->ether_type);//获得以太网的类型
  
    char ipsrcaddrstr[16]; //存储源IP地址
    char ipdstaddrstr[16]; //存储目的IP地址 
    //分析数据包二层头部，解析出上层协议
    if (ethernet_type == ETHERTYPE_IP){ //IP protocol
        //三层头部信息
        iphdrptr = (struct iphdr*)    (packet+sizeof(struct ether_header));//得到ip包头
	addr.s_addr = iphdrptr->saddr;//源IP地址
        strcpy(ipsrcaddrstr,inet_ntoa(addr));//inet_ntoa(addr)返回的地址空间是静态的，为了防止下次调用内容被覆盖，复制内容至栈空间 

        addr.s_addr = iphdrptr->daddr;//目的IP地址
        strcpy(ipdstaddrstr,inet_ntoa(addr));//inet_ntoa(addr)返回的地址空间是静态的，为了防止下次调用内容被覆盖，复制内容至栈空间

        ipheardlen = (iphdrptr->ihl)*4;//IP头部长度
    
            //四层头部信息
        tcphdrptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));//得到tcp包头
        tcpheardlen = tcphdrptr->doff*4;//TCP头部长度
    
        maciptcpheardlen = (iphdrptr->ihl)*4 + tcphdrptr->doff*4 + 14;//2-4层头部的总长度
         
        //cout <<ipsrcaddrstr<<" : "<<ntohs(tcphdrptr->source)<<" ----> "<<ipdstaddrstr<<" : "<<ntohs(tcphdrptr->dest)<<" [SYN:"<<tcphdrptr->syn<<"; ACK:"<<tcphdrptr->ack<<"]"<<endl;
	/*TCP 报文头部字段值
        tcphdrptr->seq
	tcphdrptr->ack_seq
	tcphdrptr->syn
	tcphdrptr->fin
        tcphdrptr->ack
	
	*/
    }
    data = (char*)(packet+maciptcpheardlen);//得到TCP报文内容
    string s1;
    s1 = data;
    //int AppContentLen = pkthdr->caplen - maciptcpheardlen; //应用层内容大小
    int AppContentLen = pkthdr->len - maciptcpheardlen; //应用层内容大小
    cout <<formatdatetime()<<"  "; 
    cout <<ipsrcaddrstr<<" : "<<ntohs(tcphdrptr->source)<<" ----> "<<ipdstaddrstr<<" : "<<ntohs(tcphdrptr->dest)<<" [SYN:"<<tcphdrptr->syn<<"; ACK:"<<tcphdrptr->ack<<"]"<<"caplen:"<<pkthdr->caplen<<"  maciptcpheardlen:"<<maciptcpheardlen<<"  AppContentLen:"<<AppContentLen<<endl;
   // cout<<"["<<onMessageHost(s1)<<"]";
    cout<<data;
    printf("\n\n"); 
    

}  
  

