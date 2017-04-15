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
using namespace std;
/*
以太网帧头部长度:(6+6+2)
IP头部长度:可变
TCP头部长度:


*/
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{ 
    struct in_addr ipsrcaddr;//用来表示一个32位的IPv4地址的结构体,源
    struct in_addr ipdstaddr;//用来表示一个32位的IPv4地址的结构体，目的
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
	 
        //分析三层头部信息
	iphdrptr = (struct iphdr*)    (packet+sizeof(struct ether_header));//得到ip包头
	ipsrcaddr.s_addr = iphdrptr->saddr;//源IP地址
	ipdstaddr.s_addr = iphdrptr->daddr;//目的IP地址
	ipheardlen = (iphdrptr->ihl)*4;//IP头部长度

	tcphdrptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));//得到tcp包头
	tcpheardlen = tcphdrptr->doff*4;//TCP头部长度

	maciptcpheardlen = (iphdrptr->ihl)*4 + tcphdrptr->doff*4 + 14;//2-4层头部的总长度

	cout <<inet_ntoa(ipsrcaddr)<<":"<<ntohs(tcphdrptr->source)<<" ---->"<<inet_ntoa(ipdstaddr)<<":"<<ntohs(tcphdrptr->dest)<<" [SYN:"<<tcphdrptr->syn<<"; ACK:"<<tcphdrptr->ack<<"]"<<endl;
	//cout <<"("<<ntohs(tcphdrptr->source)<<" -------->"<<ntohs(tcphdrptr->dest)<<")";
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
    //usleep(800*1000);
//去掉该注释，显示报文详细内容 
    int i;  
    //for(i=0; i<pkthdr->len; ++i) 
    //for(i=12; i<pkthdr->len; ++i)  
    for(i=0; i<(pkthdr->caplen-maciptcpheardlen); ++i)  
    { 
	unsigned char ch = data[i];
	//if(ch>=' ' && ch<='~') fputc(ch,stdout);
          //      else fputc('.',stdout);
        fputc(ch,stdout);
    }
 
    printf("\n\n"); 

}  
  
int main()  {  
    char errBuf[PCAP_ERRBUF_SIZE], * interfaceName;  
      
    interfaceName = pcap_lookupdev(errBuf); //获取网络接口设备名,如eth0 
      
    if(interfaceName)  
    { 
      cout<<"Listen on interface: "<<interfaceName<<endl<<endl; 
    }  
    else  
    {  
      printf("error: %s\n", errBuf);  
      exit(1);  
    }  
      
    pcap_t * device = pcap_open_live(interfaceName, 65535, 1, 0, errBuf); //打开一个用于捕获数据的网络接口 
      
    if(!device)  
    {  
      printf("error: pcap_open_live(): %s\n", errBuf);  
      exit(1);  
    }  
    
    /*  以下三行的注释去掉，则开启包过滤功能*/  
    struct bpf_program filter; //bpf_program结 构的指针,用于pcap_compile，格式过滤
    pcap_compile(device, &filter, "tcp port 80", 1, 0); //编译 BPF 过滤规则 
    pcap_setfilter(device, &filter); //应用 BPF 过滤规则 
      
    int id = 0; 
  
    //循环捕获网络数据包，直到遇到错误或者满足退出条件。每次捕获一个数据包就会调用 callback 指定的回调函数(此处为getPacket)
    pcap_loop(device, -1, getPacket, (u_char*)&id);  
      
    pcap_close(device); //释放网络接口 
    
    return 0;  
}  
