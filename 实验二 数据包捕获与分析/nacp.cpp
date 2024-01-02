#include<iostream>
#include <pcap.h>
#include <stdio.h>
#include <fstream>
#include <stdint.h>
#include <cstring>
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#pragma pack(1)		//�����ֽڶ��뷽ʽ
typedef struct FrameHeader_t {	//֡�ײ�
    BYTE	DesMAC[6];	// Ŀ�ĵ�ַ
    BYTE 	SrcMAC[6];	// Դ��ַ
    WORD	FrameType;	// ֡����
} FrameHeader_t;
typedef struct IPHeader_t {		//IP�ײ�     //��������д�ĵ�û�õ�
    WORD	Ver_HLen_TOS;       //�汾���ײ����Ⱥͷ�������
    WORD	TotalLen;           //�ܳ���
    WORD	ID;                 //��ʶ
    WORD	Flag_Segment;       //��־��Ƭƫ��
    WORD	TTL_Protocol;       //���ʱ���Э��
    WORD	Checksum;           //�ײ�У��� 
    ULONG	SrcIP;              //ԴIP��ַ
    ULONG	DstIP;              //Ŀ��ip��ַ
} IPHeader_t;
typedef struct Data_t {	//����֡�ײ���IP�ײ������ݰ�
    FrameHeader_t	FrameHeader;
    IPHeader_t		IPHeader;
} Data_t;

#pragma pack()	//�ָ�Ĭ�϶��뷽ʽ

void packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content);

string char2mac(BYTE* MAC)//Ŀ�ĵ�ַ��Դ��ַ
{
    string ret;
    char temp[100];
    sprintf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", int(MAC[0]), int(MAC[1]), int(MAC[2]), int(MAC[3]), int(MAC[4]), int(MAC[5]));
    ret = temp;
    return ret;
}

//pcap_loop ����ÿ�γɹ�����һ�����ݰ��󣬽���������ݰ��������Ϣ����ͷ��Ϣ�����ݰ����ݵȣ����ݸ� packet_callback �����Ĳ�����
//u_char* argument���û��Զ������ݣ�ͨ�����ڴ��ݶ������Ϣ��״̬��
//const struct pcap_pkthdr* packet_header��ָ�򲶻񵽵����ݰ��İ�ͷ��Ϣ��ָ��,�ṹ�������й����ݰ���Ԫ���ݣ���ʱ��������ݰ����ȵȡ�
//const u_char* packet_content��ָ�򲶻񵽵����ݰ������ݵ�ָ��,���Դ�����ȡ�й����ݰ�����Ϣ��

void packet_callback(u_char* argument,
                     const struct pcap_pkthdr* packet_header,
                     const u_char* packet_content)
{
    Data_t* IPPacket;
    IPPacket = (Data_t*)packet_content;                   //�� packet_content ǿ������ת��Ϊ Data_t* ���ͣ��Է����ֶ�
    WORD Kind = ntohs(IPPacket->FrameHeader.FrameType);   //֡����
                                                          //IPv4���ݰ���0x0800,  IPv6���ݰ���0x86DD,
                                                          //ARP���ݰ���0x0806,   IEEE 802.1Q VLAN ���֡��0x8100
    
    cout << "******************************************" << endl;
    cout << "֡����\t\t\t\t:" << uppercase << hex << Kind << endl;
    cout << "Ŀ��MAC��ַ\t\t:" << char2mac(IPPacket->FrameHeader.DesMAC) << endl;
    cout << "ԴMAC��ַ\t\t:" << char2mac(IPPacket->FrameHeader.SrcMAC) << endl;
    cout << "******************************************" << endl;
}

int main()
{
    pcap_if_t* alldevs; //ָ���豸����
    pcap_if_t* d;
    int num = 0;        //׼���򿪵�������
    int i = 0;          //ͳ�����������
    pcap_t* adhandle;   
    char errbuf[PCAP_ERRBUF_SIZE]; 

    //��ȡ�豸�б�
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,         //�����ӿ�
                            NULL, 
                            &alldevs,                   
                            errbuf) == -1)
    {
        cout << "find_all_dev error:" << errbuf << endl;
        return 0;
    }
    for (d = alldevs; d != NULL; d = d->next)            //��ӡ�豸�б�
    {
        cout << ++i << " " << d->name << " ";
        if (d->description)
            cout << d->description << endl;
        else
            cout << "No description����" << endl;
    }
    if (i == 0)
    {
        cout << "������" << endl;
        exit(1);
    }

   
    cout << "����׼���򿪵�������ţ�" << endl;
    cin >> num;               
    if (num < 1 || num > i) 
    {
        cout << "û�д�����" << endl;
        pcap_freealldevs(alldevs);      //�ͷ�
        exit(1);
    }

    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);   // ������ѡ�������

    if ((adhandle = pcap_open(d->name,
                              65536,                           //������Ĭ��ֵ����64KB,���������ݰ�����Ļ�������С
                              PCAP_OPENFLAG_PROMISCUOUS,
                              1000,
                              NULL, 
                              errbuf)) == NULL)
    {
        cout << " pacp_open error:" << errbuf << endl;          //��ʱ��������
        pcap_freealldevs(alldevs);
        exit(1);
    }

    pcap_freealldevs(alldevs);

    int count = -1;
    cout << "������Ҫ���������ݰ�������";
    cin >> count;
    cout << endl;

    pcap_loop(adhandle, count, packet_callback, NULL);
    //pcap_loop ���������ڲ������ݰ��ĻỰ��ѭ������ÿ�����񵽵����ݰ�
    //adhandle:�Ѵ򿪵������豸�Ự�ľ��
    //count:ָ��Ҫ��������ݰ�����
    //packet_callback:��д�Ļص��������ú�������ÿ�γɹ��������ݰ��󱻵���
    //���һ������user�����ݸ��ص��������û��Զ�������

    cout << "���ݰ��������";
    return 0;
}