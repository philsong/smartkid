/**
@file SockSupport.h 
Implementation of the winsock2

@author dream2fly
@date   20060921
@note   �����ļ�
**/
#ifndef SOCKSUPPORT_H_
#define SOCKSUPPORT_H_

#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>


#pragma comment(lib, "ws2_32.lib")

//#define STATUS_FAILED	   0xFFFF	 //�����쳣�������
#define MAX_PACK_LEN       65535	 // The max IP packet to receive.
#define MAX_ADDR_LEN       16		 // The dotted addres's length.
#define MAX_PROTO_TEXT_LEN 16		 // The length of sub protocol name(like "TCP").
#define MAX_PROTO_NUM      12		 // The count of sub protocols.
#define MAX_HOSTNAME_LAN   256		 // The max length of the host name.

/*
// The IP packet is like this. Took from RFC791.
0                   1                   2                   3   
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
//����IP�ײ�
typedef struct ip_hdr // 20 Bytes
{
	unsigned char	h_verlen;		 //4λ�ײ�����,4λIP�汾�� 
	unsigned char	tos;			 //8λ��������TOS 
	unsigned short	total_len;		 //16λ�ܳ��ȣ��ֽڣ� 
	unsigned short	ident;			 //16λ��ʶ 
	unsigned short	frag_and_flags;	 //3λ��־λ 
	unsigned char	ttl;			 //8λ����ʱ�� TTL 
	unsigned char	proto;			 //8λЭ�� (TCP, UDP ������) 
	unsigned short	checksum;		 //16λIP�ײ�У��� 
	unsigned int	sourceIP;		 //32λԴIP��ַ 
	unsigned int	destIP;			 //32λĿ��IP��ַ
}IP_HEADER;

/*
// The TCP packet is like this. Took from RFC793.
0                   1                   2                   3   
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
//����TCP�ײ�
typedef struct tcp_hdr // 20 Bytes
{
	unsigned short			th_sport;		//16λԴ�˿� 
	unsigned short			th_dport;		//16λĿ�Ķ˿� 
	unsigned int			th_seq;			//32λ���к� 
	unsigned int			th_ack;			//32λȷ�Ϻ� 
	unsigned char			th_lenres;		//4λ�ײ�����/6λ������ 
	unsigned char			th_flag;		//6λ��־λ 
	unsigned short			th_win;			//16λ���ڴ�С 
	unsigned short		    th_sum;			//16λУ��� 
	unsigned short			th_urp;			//16λ��������ƫ����
}TCP_HEADER;

/*
// The TCP's pseudo header is like this. Took from RFC793.
+--------+--------+--------+--------+
|           Source Address          |
+--------+--------+--------+--------+
|         Destination Address       |
+--------+--------+--------+--------+
|  zero  |  PTCL  |    TCP Length   |
+--------+--------+--------+--------+
*/
//����TCPα�ײ� pseudo[ 'psju:dou ]  �ٵ�,ð���
typedef struct psd_hdr // 16 Bytes
{
	unsigned long saddr; //Դ��ַ 
	unsigned long daddr; //Ŀ�ĵ�ַ 
	char mbz;			 //�ÿ�
	char ptcl;			 //Э������ 
	unsigned short tcpl; //TCP����
}PSD_HEADER;

/*
// The UDP packet is lick this. Took from RFC768.
0      7 8     15 16    23 24    31  
+--------+--------+--------+--------+ 
|     Source      |   Destination   | 
|      Port       |      Port       | 
+--------+--------+--------+--------+ 
|                 |                 | 
|     Length      |    Checksum     | 
+--------+--------+--------+--------+ 
|                                     
|          data octets ...            
+---------------- ...                 
*/
typedef struct udp_hdr  // 8 Bytes
{
	unsigned short uh_sport;	//16λԴ�˿�
	unsigned short uh_dport;	//16λĿ�Ķ˿�
	unsigned short uh_len;		//16λ����
	unsigned short uh_sum;		//16λУ���
} UDP_HEADER;

typedef struct icmp_hdr // 12 Bytes
{
	unsigned char  ih_type;			//8λ����
	unsigned char  ih_code;			//8λ����
	unsigned short ih_cksum;		//16λУ��� 
	unsigned short ih_id;			//ʶ��ţ�һ���ý��̺���Ϊʶ��ţ�
	unsigned short ih_seq;			//�������к� 
	unsigned long  ih_timestamp;	//ʱ���
}ICMP_HEADER;

// The protocol's map.
typedef struct proto_map
{
	int  ProtoNum;
	char ProtoText[MAX_PROTO_TEXT_LEN];
}PROTOMAP;

static PROTOMAP ProtoMap[MAX_PROTO_NUM]=
{
	{ IPPROTO_IP   , "IP "  },
	{ IPPROTO_ICMP , "ICMP" }, 
	{ IPPROTO_IGMP , "IGMP" },
	{ IPPROTO_GGP  , "GGP " }, 
	{ IPPROTO_TCP  , "TCP " }, 
	{ IPPROTO_PUP  , "PUP " }, 
	{ IPPROTO_UDP  , "UDP " }, 
	{ IPPROTO_IDP  , "IDP " }, 
	{ IPPROTO_ND   , "NP "  }, 
	{ IPPROTO_RAW  , "RAW " }, 
	{ IPPROTO_MAX  , "MAX " },
	{ NULL         , ""     }
};

//�������ͺ���
static u_short checksum(u_short *buffer, int size)
{
	u_long cksum=0;
	while(size >1) 
	{
		cksum+=*buffer++;
		size-=sizeof(u_short);
	}
	if(size==1) cksum+=*(u_char*)buffer;
	cksum=(cksum >> 16)+(cksum & 0xffff);
	cksum+=(cksum >> 16);
	return (u_short)(~cksum); 
}
   
//�жϲ���ϵͳ����������
typedef   enum   _OS_LEVEL{   
	WIN_UNSUP,
	WIN_NT_3_5,
	WIN_NT_3_51,
	WIN_NT_4,
	WIN_NT_4_SP2,
	WIN_NT_4_SP3,
	WIN_NT_4_SP4,
	WIN_NT_4_SP5,
	WIN_NT_4_SP6,
	WIN_2000,
	WIN_2000_SP1,
	WIN_2000_SP2,
	WIN_XP,
	WIN_XP_SP1,
	WIN_XP_SP2,
	WIN_2003
}OS_LEVEL; 

static OS_LEVEL get_win32_type()
{
	static OS_LEVEL      os_level;  
	static OSVERSIONINFO oslev;
	oslev.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&oslev);

	if (oslev.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		static unsigned int servpack = 0;
		char *pservpack;
		if (pservpack = oslev.szCSDVersion) {
			while (*pservpack && !isdigit(*pservpack)) {
				pservpack++;
			}
			if (*pservpack)
				servpack = atoi(pservpack);
		}

		if (oslev.dwMajorVersion == 3) {
			if (oslev.dwMajorVersion < 50) {
				os_level =  WIN_UNSUP;
			}
			else if (oslev.dwMajorVersion == 50) {
				os_level =  WIN_NT_3_5;
			}
			else {
				os_level =  WIN_NT_3_51;
			}
		}
		else if (oslev.dwMajorVersion == 4) {
			if (servpack < 2)
				os_level =  WIN_NT_4;
			else if (servpack <= 2)
				os_level =  WIN_NT_4_SP2;
			else if (servpack <= 3)
				os_level =  WIN_NT_4_SP3;
			else if (servpack <= 4)
				os_level =  WIN_NT_4_SP4;
			else if (servpack <= 5)
				os_level =  WIN_NT_4_SP5;
			else
				os_level =  WIN_NT_4_SP6;
		}
		else if (oslev.dwMajorVersion == 5) {
			if (oslev.dwMinorVersion == 0) {
				if (servpack == 0)
					os_level =  WIN_2000;
				else if (servpack == 1)
					os_level =  WIN_2000_SP1;
				else
					os_level =  WIN_2000_SP2;
			}
			else if (oslev.dwMinorVersion == 2) {
				os_level =  WIN_2003;
			}
			else if (oslev.dwMinorVersion == 1){
				if (servpack < 1)
					os_level =  WIN_XP;
				else if (servpack == 1)
					os_level =  WIN_XP_SP1;
				else
					os_level =  WIN_XP_SP2;
			}
		}
		else {
			os_level =  WIN_UNSUP;
		}
	}

	return  os_level;
}

//------------------------------------------------------------ 
// �� ����TransformIp(char* addr,DWORD &dwIP,bool flag) 
// �� ����char* addr,DWORD &dwIP,bool flag 
// ����ֵ������ɹ�����true�����ɹ�������false 
// �� �����ַ�����IP��DWORD��IPת��.��Ϊ��ʱ����DWORD��IPת��Ϊ�ַ�������Ϊ��ʱת��ΪDWORD�� 
//------------------------------------------------------------ 
static bool TransformIp(char* addr,DWORD &dwIP,bool flag) //ע�⣺�����dwIP��������Ϊ�����ֽ�ѭ��
{ 
	//char ת��Ϊ DWORD 
	if (flag) 
	{ 		
		char* ipaddr = NULL; 
		in_addr inaddr; 
		inaddr.s_addr=dwIP; 
		ipaddr= inet_ntoa(inaddr); 
		strcpy(addr,ipaddr); 
		return true; 
	} 
	//DWORD ת��Ϊ char
	else 
	{ 
		dwIP = inet_addr(addr); 
		return true; 
	} 
}

static bool getlocalip(char* localip)
{
	char hostname[256]={0};
	int ret = gethostname(hostname, sizeof(hostname));
	if(ret==SOCKET_ERROR)
	{
		return false;
	}
	hostent* pHostent = gethostbyname(hostname);
	for (int nAdapter=0; pHostent->h_addr_list[nAdapter]; nAdapter++) 
	{
		char* ipaddr = NULL; 
		in_addr inaddr; 
		inaddr.s_addr=*(DWORD*)pHostent->h_addr_list[nAdapter]; 
		ipaddr= inet_ntoa(inaddr); 
		strcpy(localip,ipaddr); 
		//localip++;
		break;//just ��ʱ�������
	}

	return true;
}

static unsigned long MakeRand32(int i) 
{ 
	unsigned long j1,j2,s; 

	i = i << 15; 

	//srand( (unsigned int)time(NULL) + i ); 

	j1 = rand()+i; 
	j2 = rand()+i; 

	j1 = j1 << 16; 

	s = j1+j2; 

	return s; 
} 

static unsigned short MakeRand16(int i) 
{ 
	unsigned short s; 

	i = i << 15; 

	//srand( (unsigned int)time(NULL) +i ); 
	s = rand()+i; 

	return s; 
} 

static int PrintError(const char* strErr)
{
	LPTSTR lpErr=0;
	DWORD dwError;
	dwError=WSAGetLastError();
	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, 
		NULL, dwError,LANG_NEUTRAL, 
		lpErr, 0, NULL);
	TRACE("\n\tFail:%s, Reason:%d/%s , at line %d  in %s\n\n",strErr,dwError,lpErr,__LINE__,__FILE__);
	exit(EXIT_FAILURE);
}

enum link_type
{
	_CONNECT,
	_SYN,
	_ICMP,
	_TCP,
	_UDP
};

///////////////////////
class CSockSupport
{
public:
	CSockSupport(bool bAuto = true);
	~CSockSupport(void);
	int Init();
	int Uninit();

	// Check whether the winsock is initialized(supported).
	bool IsSupported();
private:
	bool m_bSupported;
};

#endif
