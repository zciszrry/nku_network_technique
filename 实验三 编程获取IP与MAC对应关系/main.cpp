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
struct FrameHeader_t //֡�ײ�
{
	BYTE DesMAC[6];  //Ŀ�ĵ�ַ
	BYTE SrcMAC[6];  //Դ��ַ
	WORD FrameType;  //֡����
};

struct ARPFrame_t               //ARP֡
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;			//Ӳ�����ͣ���̫��Ϊ1
	WORD ProtocolType;			//Э�����ͣ�ip����Ϊ0800H
	BYTE HLen;					//Ӳ����ַ���ȣ���̫��Mac��ַ����Ϊ6B
	BYTE PLen;					//Э���ַ���ȣ�ip��ַ����Ϊ4B
	WORD Operation;				//����������1Ӧ��2
	BYTE SendHa[6];				//ԴMac
	DWORD SendIP;				//Դip
	BYTE RecvHa[6];				//Ŀ��Mac
	DWORD RecvIP;				//Ŀ��ip
};
#pragma pack()        //�ָ�ȱʡ���뷽ʽ

//��ӡip��Mac��Ӧ��ϵ
void printIP2MAC(ARPFrame_t* IPPacket)
{
	cout << "ip��Mac��ַ��Ӧ��ϵΪ�� ";

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
	pcap_if_t* alldevs;				//�豸�б��ײ�ָ��
	pcap_if_t* ptr;					//���ڵ���
	pcap_addr_t* a;					//����ip��ַ����
	char errbuf[PCAP_ERRBUF_SIZE];  //������Ϣ������
	int index = 0;					//�������

	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
							NULL, 
							&alldevs,
							errbuf
							) == -1)
	{
		cout << "��ȡ����ӿ�ʱ��������:" << errbuf << endl;
		return 0;
	}
	//��ӡ
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)//������ȡ���豸
	{
		cout << endl;
		cout <<"  "<< index + 1 << "\t" << ptr->name << endl;
		if (ptr->description) 
		{
			cout << "  ������" << ptr->description << endl;
		}
		else
		{
			cout << "No Description." << endl;
		}

		for (a = ptr->addresses; a != NULL; a = a->next)//ÿ�������ӿڿ��ж��ip��ַ
		{
			if (a->addr->sa_family == AF_INET)
			{

				cout << "  IP��ַ��\t\t" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  �������룺\t\t" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
				cout << "  �㲥��ַ��\t\t" << inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr) << endl;
			}
		}
		index++;
	}

	int n;
	cout << "���뽫Ҫ�򿪵������ţ�";
	cin >> n;
	if (n<1 || n>index)
	{
		cout << "����������Χ��" << endl;
		exit(1);
	}
	ptr = alldevs;
	for (int i = 1; i < n; i++)//������׼���򿪵�����
	{
		ptr = ptr->next;
	}

	//������
	pcap_t* pcap_handle = pcap_open(ptr->name, 
									65536,						//��󳤶�
									PCAP_OPENFLAG_PROMISCUOUS,
									1000,                       //���ʱ��
									NULL,
									errbuf);
	if (pcap_handle == NULL)
	{
		cout << "�޷���������" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "�ɹ�������" << endl << endl;
	}

	//��װARP����
	ARPFrame_t ARPFrame;
	DWORD SendIP;
	DWORD RevIP;
	for (int i = 0; i < 6; i++)					//Mac����Ϊ6B
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;  //�㲥��255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;  //��ٵ�ԴMac��66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;					//Ŀ��Mac���ȳ�ʼΪΪ0
		ARPFrame.SendHa[i] = 0x66;				//ԴMac
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);	//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);			//Ӳ������̫��
	ARPFrame.ProtocolType = htons(0x0800);			//Э�飺ΪIP
	ARPFrame.HLen = 6;							
	ARPFrame.PLen = 4;	
	ARPFrame.Operation = htons(0x0001);				//������ARP����
	SendIP = ARPFrame.SendIP = htonl(0x70707070);	//��ٵ�Դip��ַ��112.112.112.112.112.112

	//��ѡ����IP��ΪĿ��ip��ַ
	//ptr�Ѿ���������ѡ����
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)//�жϸõ�ַ�Ƿ�Ϊip��ַ
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}

	//p,buf,size:���������ݰ�����С
	//�ɹ�����0�����򷵻�-1

	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

	//������ѡ�������ݰ�
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "  �������ݰ�ʱ��������" << errbuf << endl;
			return 0;
		}
		else if (rtn == 0)
		{
				cout << "  û�в������ݱ�" << endl;
		}
		else
		{
			IPPacket = (ARPFrame_t*)pkt_data;

			//��Ӧ���ĵ�ԴipӦΪ��ѡ����ip��Ŀ��ipΪ��ٵ�112.112.112.112.112.112
			if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//�ж��Ƿ�Ϊ���ͱ��ĵ���Ӧ
			{
				printIP2MAC(IPPacket);
				break;
			}
		}
	}

	//�����緢�����ݰ�
	cout << "\n" << endl;
	cout << "������Ŀ��ip��ַ:";
	char str[15];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);		//Ŀ��ip
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;	//Դip������Ӧ���ĵ�Դip������ѡ����ip
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i]; //����Mac�����±��ĵ�ԴMac
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP������ʧ��" << endl;
		exit(1);
	}
	//�ٴβ���
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "  �������ݰ�ʱ��������" << errbuf << endl;
			return 0;
		}
		else if (rtn == 0)
		{
			cout << "  û�в������ݱ�" << endl;
		}
		else
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//��Ӧ����
			{
				printIP2MAC(IPPacket);
				break;
			}
		}
	}
}