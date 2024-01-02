#include<iostream>
#include <pcap.h>
#include <stdio.h>
#include <fstream>
#include <stdint.h>
#include <cstring>
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t {	//帧首部
    BYTE	DesMAC[6];	// 目的地址
    BYTE 	SrcMAC[6];	// 源地址
    WORD	FrameType;	// 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {		//IP首部     //书上这样写的但没用到
    WORD	Ver_HLen_TOS;       //版本、首部长度和服务类型
    WORD	TotalLen;           //总长度
    WORD	ID;                 //标识
    WORD	Flag_Segment;       //标志和片偏移
    WORD	TTL_Protocol;       //存活时间和协议
    WORD	Checksum;           //首部校验和 
    ULONG	SrcIP;              //源IP地址
    ULONG	DstIP;              //目的ip地址
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
    FrameHeader_t	FrameHeader;
    IPHeader_t		IPHeader;
} Data_t;

#pragma pack()	//恢复默认对齐方式

void packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content);

string char2mac(BYTE* MAC)//目的地址与源地址
{
    string ret;
    char temp[100];
    sprintf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", int(MAC[0]), int(MAC[1]), int(MAC[2]), int(MAC[3]), int(MAC[4]), int(MAC[5]));
    ret = temp;
    return ret;
}

//pcap_loop 会在每次成功捕获一个数据包后，将捕获的数据包的相关信息（包头信息、数据包内容等）传递给 packet_callback 函数的参数。
//u_char* argument：用户自定义数据，通常用于传递额外的信息或状态。
//const struct pcap_pkthdr* packet_header：指向捕获到的数据包的包头信息的指针,结构包含了有关数据包的元数据，如时间戳、数据包长度等。
//const u_char* packet_content：指向捕获到的数据包的内容的指针,可以从中提取有关数据包的信息。

void packet_callback(u_char* argument,
                     const struct pcap_pkthdr* packet_header,
                     const u_char* packet_content)
{
    Data_t* IPPacket;
    IPPacket = (Data_t*)packet_content;                   //将 packet_content 强制类型转换为 Data_t* 类型，以访问字段
    WORD Kind = ntohs(IPPacket->FrameHeader.FrameType);   //帧类型
                                                          //IPv4数据包：0x0800,  IPv6数据包：0x86DD,
                                                          //ARP数据包：0x0806,   IEEE 802.1Q VLAN 标记帧：0x8100
    
    cout << "******************************************" << endl;
    cout << "帧类型\t\t\t\t:" << uppercase << hex << Kind << endl;
    cout << "目的MAC地址\t\t:" << char2mac(IPPacket->FrameHeader.DesMAC) << endl;
    cout << "源MAC地址\t\t:" << char2mac(IPPacket->FrameHeader.SrcMAC) << endl;
    cout << "******************************************" << endl;
}

int main()
{
    pcap_if_t* alldevs; //指向设备链表
    pcap_if_t* d;
    int num = 0;        //准备打开的网卡号
    int i = 0;          //统计网卡，编号
    pcap_t* adhandle;   
    char errbuf[PCAP_ERRBUF_SIZE]; 

    //获取设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,         //本机接口
                            NULL, 
                            &alldevs,                   
                            errbuf) == -1)
    {
        cout << "find_all_dev error:" << errbuf << endl;
        return 0;
    }
    for (d = alldevs; d != NULL; d = d->next)            //打印设备列表
    {
        cout << ++i << " " << d->name << " ";
        if (d->description)
            cout << d->description << endl;
        else
            cout << "No description……" << endl;
    }
    if (i == 0)
    {
        cout << "无网卡" << endl;
        exit(1);
    }

   
    cout << "输入准备打开的网卡编号：" << endl;
    cin >> num;               
    if (num < 1 || num > i) 
    {
        cout << "没有此网卡" << endl;
        pcap_freealldevs(alldevs);      //释放
        exit(1);
    }

    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);   // 迭代到选择的网卡

    if ((adhandle = pcap_open(d->name,
                              65536,                           //常见的默认值，即64KB,决定了数据包捕获的缓冲区大小
                              PCAP_OPENFLAG_PROMISCUOUS,
                              1000,
                              NULL, 
                              errbuf)) == NULL)
    {
        cout << " pacp_open error:" << errbuf << endl;          //打开时出错，结束
        pcap_freealldevs(alldevs);
        exit(1);
    }

    pcap_freealldevs(alldevs);

    int count = -1;
    cout << "请输入要解析的数据包数量：";
    cin >> count;
    cout << endl;

    pcap_loop(adhandle, count, packet_callback, NULL);
    //pcap_loop 函数用于在捕获数据包的会话中循环处理每个捕获到的数据包
    //adhandle:已打开的网络设备会话的句柄
    //count:指定要捕获的数据包数量
    //packet_callback:编写的回调函数，该函数将在每次成功捕获数据包后被调用
    //最后一个参数user：传递给回调函数的用户自定义数据

    cout << "数据包捕获完成";
    return 0;
}