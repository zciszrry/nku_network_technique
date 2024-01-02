#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996 )
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;

#pragma pack(1)
struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
};

struct ARPFrame_t               //ARP帧
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;			//硬件类型：以太网为1
	WORD ProtocolType;			//协议类型：ip类型为0800H
	BYTE HLen;					//硬件地址长度：以太网Mac地址长度为6B
	BYTE PLen;					//协议地址长度：ip地址长度为4B
	WORD Operation;				//操作：请求1应答2
	BYTE SendHa[6];				//源Mac
	DWORD SendIP;				//源ip
	BYTE RecvHa[6];				//目的Mac
	DWORD RecvIP;				//目的ip
};
#pragma pack()        //恢复缺省对齐方式

//打印ip和Mac对应关系
void printIP2MAC(ARPFrame_t* IPPacket)
{
	cout << "ip与Mac地址对应关系为： ";

	BYTE* p = (BYTE*)&IPPacket->SendIP;
	for (int i = 0; i < 3; i++)
	{
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p;
	cout << "	-----	";
	for (int i = 0; i < 6; i++)
	{
		if(i!=5)
			printf("%02x:", IPPacket->SendHa[i]);
		else
			printf("%02x", IPPacket->SendHa[i]);	
	}
	cout << endl;
}

int main()
{
	pcap_if_t* alldevs;				//设备列表首部指针
	pcap_if_t* ptr;					//用于迭代
	pcap_addr_t* a;					//用于ip地址遍历
	char errbuf[PCAP_ERRBUF_SIZE];  //错误信息缓冲区
	int index = 0;					//网卡编号

	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
							NULL, 
							&alldevs,
							errbuf
							) == -1)
	{
		cout << "获取网络接口时发生错误:" << errbuf << endl;
		return 0;
	}
	//打印
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)//遍历获取的设备
	{
		cout << endl;
		cout <<"  "<< index + 1 << "\t" << ptr->name << endl;
		if (ptr->description) 
		{
			cout << "  描述：" << ptr->description << endl;
		}
		else
		{
			cout << "No Description." << endl;
		}

		for (a = ptr->addresses; a != NULL; a = a->next)//每个网卡接口可有多个ip地址
		{
			if (a->addr->sa_family == AF_INET)
			{

				cout << "  IP地址：\t\t" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  网络掩码：\t\t" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
				cout << "  广播地址：\t\t" << inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr) << endl;
			}
		}
		index++;
	}

	int n;
	cout << "输入将要打开的网卡号：";
	cin >> n;
	if (n<1 || n>index)
	{
		cout << "不在网卡范围！" << endl;
		exit(1);
	}
	ptr = alldevs;
	for (int i = 1; i < n; i++)//迭代到准备打开的网卡
	{
		ptr = ptr->next;
	}

	//打开网卡
	pcap_t* pcap_handle = pcap_open(ptr->name, 
									65536,						//最大长度
									PCAP_OPENFLAG_PROMISCUOUS,
									1000,                       //最大时间
									NULL,
									errbuf);
	if (pcap_handle == NULL)
	{
		cout << "无法打开网卡：" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "成功打开网卡" << endl << endl;
	}

	//组装ARP报文
	ARPFrame_t ARPFrame;
	DWORD SendIP;
	DWORD RevIP;
	for (int i = 0; i < 6; i++)					//Mac长度为6B
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;  //广播：255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;  //虚假的源Mac：66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;					//目的Mac，先初始为为0
		ARPFrame.SendHa[i] = 0x66;				//源Mac
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);	//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);			//硬件：以太网
	ARPFrame.ProtocolType = htons(0x0800);			//协议：为IP
	ARPFrame.HLen = 6;							
	ARPFrame.PLen = 4;	
	ARPFrame.Operation = htons(0x0001);				//操作：ARP请求
	SendIP = ARPFrame.SendIP = htonl(0x70707070);	//虚假的源ip地址：112.112.112.112.112.112

	//所选网卡IP设为目的ip地址
	//ptr已经迭代到所选网卡
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)//判断该地址是否为ip地址
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}

	//p,buf,size:网卡，数据包，大小
	//成功返回0，否则返回-1

	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

	//捕获所选网卡数据包
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "  捕获数据包时发生错误：" << errbuf << endl;
			return 0;
		}
		else if (rtn == 0)
		{
				cout << "  没有捕获到数据报" << endl;
		}
		else
		{
			IPPacket = (ARPFrame_t*)pkt_data;

			//响应报文的源ip应为所选网卡ip，目的ip为虚假的112.112.112.112.112.112
			if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//判断是否为发送报文的响应
			{
				printIP2MAC(IPPacket);
				break;
			}
		}
	}

	//向网络发送数据包
	cout << "\n" << endl;
	cout << "请输入目的ip地址:";
	char str[15];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);		//目的ip
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;	//源ip，即响应报文的源ip，即所选网卡ip
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i]; //网卡Mac给到新报文的源Mac
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP请求发送失败" << endl;
		exit(1);
	}
	//再次捕获
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "  捕获数据包时发生错误：" << errbuf << endl;
			return 0;
		}
		else if (rtn == 0)
		{
			cout << "  没有捕获到数据报" << endl;
		}
		else
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//响应报文
			{
				printIP2MAC(IPPacket);
				break;
			}
		}
	}
}