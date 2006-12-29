#include "StdAfx.h"
#include "socksupport.h"
#include "smartkidDlg.h"
#include "portscan.h"
#include ".\portscan.h"

static const u_short ports_to_scan[] = 
{
	7,9,11,13,17,18,19,21,22,23,
		25,37,38,39,43,49,53,66,67,68,
		70,79,80,88,103,107,110,111,118,123,135,
		137,138,139,156,161,162,204,427,445,512,
		513,514,515,519,554,556,634,666,749,762,
		1025,1080,1155,1366,1417,1433,1434,1498,1521,1524,
		1525,3128,3306,3389,4000,4001,4400,4672,4899,5190,
		5631,6000,8080,12345
};	

CCriticalSection CPortScan::m_Sync;
link_type	CPortScan::m_scantype;
u_short 	CPortScan::m_ncounter=0;
u_short 	CPortScan::m_threadnum=0;
u_short 	CPortScan::m_portnum=0;
u_short 	CPortScan::m_mainnum=0;
u_short		CPortScan::m_listCounter=0;
char		CPortScan::m_source_ip[16]={0};
char		CPortScan::m_target_ip[16]={0};
u_short		CPortScan::m_target_port;
u_short		CPortScan::m_start_port;
u_short		CPortScan::m_end_port;
bool		CPortScan::m_isspecial;

volatile SOCKET	CPortScan::sock;
SOCKET	CPortScan::recv_sock=INVALID_SOCKET;
SOCKADDR_IN CPortScan::connect_in;
SOCKADDR_IN CPortScan::synscan_in; 


volatile	IP_HEADER  CPortScan::ipheader;  
volatile	TCP_HEADER CPortScan::tcpheader;  
volatile	PSD_HEADER CPortScan::psdheader;


CsmartkidDlg* CPortScan::m_pDlg=0;


CPortScan::CPortScan(void)
{
}

CPortScan::~CPortScan(void)
{
}

void CPortScan::start_scan()
{
	//������ʼ��	
	m_listCounter=0;
	m_ncounter=0;
	m_pDlg=(CsmartkidDlg*)AfxGetApp()->GetMainWnd();

	m_threadnum=m_pDlg->m_threadnum;
	m_isspecial=m_pDlg->m_isspecial;
	m_scantype=m_pDlg->m_scantype;
	strcpy(m_source_ip,m_pDlg->m_localip.GetBuffer());
	strcpy(m_target_ip,m_pDlg->m_targetip.GetBuffer());
	m_start_port=m_pDlg->m_startport;
	m_end_port=m_pDlg->m_endport;

	if(m_isspecial)
	{
		m_portnum=sizeof(ports_to_scan)/sizeof(*ports_to_scan);
	}
	else
	{
		m_portnum=m_end_port-m_start_port+1;
	}

	m_mainnum=m_portnum/m_threadnum;
	if(m_portnum%m_threadnum > 0)
	{
		m_mainnum++;
	}

	m_pDlg->m_prog->SetRange(0,m_portnum);
	m_pDlg->m_prog->SetStep(1);

	AfxBeginThread(scanthread,NULL);
}

UINT CPortScan::scanthread(LPVOID param)
{
	CWinThread *wt[1024];
	HANDLE hThread[1024];
	u_short port;				
	u_short nThreadCounter;
	//�������Ͱ��߳�
	switch(m_scantype) 
	{
	case _CONNECT:
		{
			if(m_isspecial)
			{
				for(int i=0;i<m_mainnum;i++)
				{
					nThreadCounter=0;
					//ÿ�������������߳�ʵ�ʸ���,���һ����һ������ֵ
					for(int j=0;j<m_threadnum;j++)
					{
						if(g_stop==true)
						{
							break;
						}
						if(m_ncounter>m_portnum-1)
						{
							break;
						}
						//��ѭ������
						nThreadCounter++;
						m_pDlg->m_prog->StepIt();
						port=ports_to_scan[m_ncounter];
						wt[j]=AfxBeginThread(conect_scanthread,(LPVOID)port);
						hThread[j]=wt[j]->m_hThread;
					}
					hThread[j]=NULL;//�ǳ���Ҫ,��Ϊ��ִ��if(m_ncounter>m_portnum-1)ʱ���жϵģ���ʱhThread[j]��ֵ
					//���k=0����ʾû�п����߳�
					if(j!=0)
					{
						//WaitForMultipleObjects(nThreadCounter,hThread,TRUE,INFINITE);
						WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
					}
				}
			}
			else
			{
				u_short nowport=m_start_port;
				for(int i=0;i<m_mainnum;i++)
				{
					nThreadCounter=0;
					//ÿ�������������߳�ʵ�ʸ���,���һ����һ������ֵ
					for(int j=0;j<m_threadnum;j++)
					{
						if(g_stop==true)
						{
							break;
						}
						if(m_ncounter>m_portnum-1)
						{
							break;
						}
						//��ѭ������
						nThreadCounter++;
						m_pDlg->m_prog->StepIt();
						port=nowport++;
						wt[j]=AfxBeginThread(conect_scanthread,(LPVOID)port);
						hThread[j]=wt[j]->m_hThread;
					}
					hThread[j]=NULL;//�ǳ���Ҫ,��Ϊ��ִ��if(m_ncounter>m_portnum-1)ʱ���жϵģ���ʱhThread[j]��ֵ
					//���k=0����ʾû�п����߳�
					if(j!=0)
					{
						//WaitForMultipleObjects(nThreadCounter,hThread,TRUE,INFINITE);
						WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
					}
				}
			}
			break;
		}			
	case _SYN:
		{			
			//��ʼ��Syn���ݰ�
			InitSynPacket(); 
			AfxBeginThread(recv_packet_thread,NULL);

			if(m_isspecial)
			{
				for(int i=0;i<m_mainnum;i++)
				{
					nThreadCounter=0;
					//ÿ�������������߳�ʵ�ʸ���,���һ����һ������ֵ
					for(int j=0;j<m_threadnum;j++)
					{
						if(g_stop==true)
						{
							break;
						}
						if(m_ncounter>m_portnum-1)
						{
							break;
						}
						//��ѭ������
						nThreadCounter++;
						m_pDlg->m_prog->StepIt();
						port=ports_to_scan[m_ncounter];
						wt[j]=AfxBeginThread(syn_scanthread,(LPVOID)port);
						hThread[j]=wt[j]->m_hThread;
						Sleep(10);
					}
					hThread[j]=NULL;//�ǳ���Ҫ,��Ϊ��ִ��if(m_ncounter>m_portnum-1)ʱ���жϵģ���ʱhThread[j]��ֵ
					//���k=0����ʾû�п����߳�
					if(j!=0)
					{
						//WaitForMultipleObjects(nThreadCounter,hThread,TRUE,INFINITE);
						WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
					}
				}
			}
			else
			{
				u_short nowport=m_start_port;
				for(int i=0;i<m_mainnum;i++)
				{
					nThreadCounter=0;
					//ÿ�������������߳�ʵ�ʸ���,���һ����һ������ֵ
					for(int j=0;j<m_threadnum;j++)
					{
						if(g_stop==true)
						{
							break;
						}
						if(m_ncounter>m_portnum-1)
						{
							break;
						}
						//��ѭ������
						nThreadCounter++;
						m_pDlg->m_prog->StepIt();
						port=nowport++;
						wt[j]=AfxBeginThread(syn_scanthread,(LPVOID)port);
						hThread[j]=wt[j]->m_hThread;
					}
					hThread[j]=NULL;//�ǳ���Ҫ,��Ϊ��ִ��if(m_ncounter>m_portnum-1)ʱ���жϵģ���ʱhThread[j]��ֵ
					//���k=0����ʾû�п����߳�
					if(j!=0)
					{
						//WaitForMultipleObjects(nThreadCounter,hThread,TRUE,INFINITE);
						WaitForMultipleObjects(nThreadCounter,hThread,TRUE,500);
					}
				}
			}
			break;
		}
	}
	closesocket(sock);
	m_pDlg->m_prog->SetPos(0);
	return 0;
}

void CPortScan::InitCnnPacket()
{
	sock=socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(sock ==INVALID_SOCKET)
	{  
		PrintError("socket");
	}

	//���÷��ͳ�ʱʱ��
	int nTimeOut=200;		///<3 second
	/*int setsockopt(int socket,int level,int optname,const char *optval,socklen_t optlen)*/
	int ret;
	ret=setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(char *)&nTimeOut,sizeof(nTimeOut));
	if(ret==SOCKET_ERROR)
	{
		PrintError("setsockopt");
	}
	//���ý��ճ�ʱʱ��
	nTimeOut=200;
	ret=setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&nTimeOut,sizeof(nTimeOut));
	if(ret==SOCKET_ERROR)
	{
		PrintError("setsockopt");
	}

	memset((void *)&connect_in,0,sizeof(connect_in));
	connect_in.sin_family=AF_INET;
	connect_in.sin_addr.s_addr=inet_addr(m_target_ip);
}

UINT CPortScan::conect_scanthread(LPVOID param)
{
	m_Sync.Lock();
	m_ncounter++;	
	m_Sync.Unlock();

	u_short now_port=(u_short)param;

	InitCnnPacket();
	connect_in.sin_port=htons(now_port);

	/*ret 0 success; -1 error*/
	int ret=connect(sock,(struct sockaddr*)&connect_in,sizeof(connect_in));
	if(!ret)
	{			
		CString open_port;
		open_port.Format("%d",now_port);
		m_pDlg->m_listInfo.InsertItem(m_listCounter,m_target_ip,0);
		m_pDlg->m_listInfo.SetItemText(m_listCounter,1,open_port);
		m_listCounter++;
		return 1;
	}

	return 0;
}

void CPortScan::InitSynPacket()
{
	//���Ŀ�����
	memset((void *)&synscan_in,0,sizeof(synscan_in));
	synscan_in.sin_family = AF_INET;  
	synscan_in.sin_addr.s_addr = inet_addr(m_target_ip); 

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
	ipheader.sourceIP=inet_addr(m_source_ip);
	ipheader.destIP=inet_addr(m_target_ip);  

	//���Tcp�ײ� 
	memset((void *)&tcpheader,0,sizeof(tcpheader));
	tcpheader.th_dport=htons(0);		   //��ʼ��ʱ��ʱֵ
	tcpheader.th_sport=htons(0);  
	tcpheader.th_seq=htonl(0x19840102);  
	tcpheader.th_ack=0;  
	tcpheader.th_lenres=(sizeof(TCP_HEADER)/4<<4|0);  
	tcpheader.th_flag=2;				   //syn 00000010 �޸�������ʵ�ֲ�ͬ�ı�־λ̽�⣬2��SYN��1��FIN��16��ACK̽�� 
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

UINT CPortScan::syn_scanthread(LPVOID param)
{
	m_Sync.Lock();
	m_ncounter++;	
	m_Sync.Unlock();

	u_short now_port=(u_short)param;

	sock=WSASocket(AF_INET,SOCK_RAW,IPPROTO_RAW,NULL,0,WSA_FLAG_OVERLAPPED);
	if(sock ==INVALID_SOCKET)
	{  
		PrintError("WSASocket");
	}

	//����IP_HDRINCL���Լ����IP�ײ�
	BOOL flag=true;  
	int ret=setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(char*)&flag,sizeof(flag));
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("setsockopt");	
	}  
	//���÷��ͳ�ʱʱ��
	int nTimeOut =2000;//2s  
	ret=setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(char*)&nTimeOut,sizeof(nTimeOut)); 
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("setsockopt");	
	} 
	//���ý��ճ�ʱʱ��
	nTimeOut=1000;
	ret=setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&nTimeOut,sizeof(nTimeOut));
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("setsockopt");	
	} 

	//����Ŀ��˿�
	synscan_in.sin_port = htons(now_port); 
	//����ipУ���Ϊ0
	ipheader.checksum=0;  
	//����Ŀ��˿�
	tcpheader.th_dport=htons(now_port);  
	//����tcpУ���Ϊ0
	tcpheader.th_sum = 0;	

	//����У���  
	char SendBuff[256]={0};  

	//����TCPУ��� 
	memcpy(SendBuff, (void *)&psdheader, sizeof(PSD_HEADER));  
	memcpy(SendBuff+sizeof(PSD_HEADER), (void *)&tcpheader, sizeof(TCP_HEADER));  
	tcpheader.th_sum=checksum((u_short *)SendBuff,sizeof(PSD_HEADER)+sizeof(TCP_HEADER)); 

	//����IP�����
	memcpy(SendBuff, (void *)&ipheader, sizeof(IP_HEADER));  
	memcpy(SendBuff+sizeof(IP_HEADER),(void *) &tcpheader, sizeof(TCP_HEADER));  //�˴��Ѿ�������TCP����
	memset(SendBuff+sizeof(IP_HEADER)+sizeof(TCP_HEADER),0,4);
	ipheader.checksum=checksum((u_short *)SendBuff,sizeof(IP_HEADER));
	memcpy(SendBuff, (void *)&ipheader, sizeof(IP_HEADER)); //��Ϊipheaderͷ�ı��ˣ����¸���ipheader����

	//�������У��͵�IP�ײ���TCP�ײ����Ƶ�ͬһ���������оͿ���ֱ�ӷ��� 
	//�������ݰ�  
	ret=sendto(sock, SendBuff, sizeof(IP_HEADER)+sizeof(TCP_HEADER), 0, (struct sockaddr*)&synscan_in, sizeof(synscan_in));  
	if(ret==SOCKET_ERROR)  
	{  
		closesocket(sock);
		PrintError("sendto");	//XP sp2��raw socket send() 10004 Error,xp sp2�²�֧��raw socket
	}  

	closesocket(sock);
	return 0;  
}

UINT CPortScan::recv_packet_thread(LPVOID param) 
{ 
	//����socket�������ݰ� 
	if ((recv_sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET) 
	{ 
		PrintError("WSASocket");	//XP sp2��raw socket send() 10004 Error,xp sp2�²�֧��raw socket
	} 

	SOCKADDR_IN Source; 
	memset((void *)&Source,0,sizeof(Source));
	Source.sin_family = AF_INET; 
	Source.sin_port = htons(0); 
	Source.sin_addr.s_addr = inet_addr(m_source_ip); 

	//�󶨵����ض˿� 
	if(bind(recv_sock, (PSOCKADDR)&Source, sizeof(Source))) 
	{ 
		closesocket(recv_sock);
		PrintError("bind");	//XP sp2��raw socket send() 10004 Error,xp sp2�²�֧��raw socket
	} 

	//DWORD dwValue; 
	//ioctlsocket(recv_sock, SIO_RCVALL, &dwValue); 
	//����SOCK_RAWΪSIO_RCVALL���Ա�������е�IP�� 
	DWORD dwBufferLen[10] ; 
	DWORD dwBufferInLen = 1 ; 
	DWORD dwBytesReturned = 0 ; 
	if(WSAIoctl(sock,SIO_RCVALL,&dwBufferInLen,sizeof(dwBufferInLen),&dwBufferLen,sizeof(dwBufferLen),&dwBytesReturned,NULL,NULL))
	{
		closesocket(recv_sock);
		PrintError("sendto");
	}

	//��ʼ�������ݰ� 
	char RecvBuf[65535]={0}; 
	int bytesRcved;
	while(1) 
	{ 
		memset(RecvBuf, 0, sizeof(RecvBuf)); 
		bytesRcved=recv(recv_sock, RecvBuf, sizeof(RecvBuf), 0); 
		if(bytesRcved == 0)
		{
			continue;
		}
		else if(bytesRcved==SOCKET_ERROR)
		{
			if(GetLastError()==WSAETIMEDOUT)	
			{
				continue;
			}
			else
			{
				closesocket(recv_sock);
				PrintError("recvfrom");
			}
		}
		check_port(RecvBuf); 
	} 

	closesocket(recv_sock);

	return 0; 
}

void CPortScan::check_port(char *RecvBuffer) 
{ 
	IP_HEADER        *ipHeader;//IP_HEADER��ָ�� 
	TCP_HEADER       *tcpHeader;//TCP_HEADER��ָ�� 

	ipHeader = (IP_HEADER *)RecvBuffer; 
	tcpHeader = (TCP_HEADER *) (RecvBuffer+sizeof(IP_HEADER)); 

	if(ipHeader->sourceIP != inet_addr(m_target_ip)) 
	{ 
		return; 
	} 
	if (tcpHeader->th_flag == 20 || tcpHeader->th_flag == 4)        // No Service Exists, No Port Is Open Then 
	{ 
		return;        // Found None 
	} 

	if(m_isspecial)
	{
		// Check All The Ports 
		for (UINT i = 0 ; i < m_portnum ; i++) 
		{ 
			if (tcpHeader->th_flag == 18 && tcpHeader->th_sport == htons(ports_to_scan[i]))        // We Get The Open Port 
			{ 
				CString open_port;
				open_port.Format("%d",ntohs(tcpHeader->th_sport));
				m_pDlg->m_listInfo.InsertItem(m_listCounter,m_target_ip,0);
				m_pDlg->m_listInfo.SetItemText(m_listCounter,1,open_port);
				m_listCounter++;
			} 
		} 
	}
	else
	{
		u_short nowport=m_start_port;
		for (UINT i = 0 ; i < m_portnum ; i++,nowport++) 
		{ 
			if (tcpHeader->th_flag == 18 && tcpHeader->th_sport == htons(nowport))        // We Get The Open Port 
			{ 
				CString open_port;
				open_port.Format("%d",ntohs(tcpHeader->th_sport));
				m_pDlg->m_listInfo.InsertItem(m_listCounter,m_target_ip,0);
				m_pDlg->m_listInfo.SetItemText(m_listCounter,1,open_port);
				m_listCounter++;
			} 
		} 
	}
}

