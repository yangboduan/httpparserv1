#include <string.h>
#include <pcap.h>  
#include <iostream>
#include <stdlib.h>
#include "getpacket.h"
using namespace std;
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
