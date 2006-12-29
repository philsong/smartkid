#pragma once

class CsmartkidDlg;

class CPortScan
{
public:
	CPortScan(void);
	~CPortScan(void);	
	void start_scan();

private:	
	static UINT scanthread(LPVOID);
	static void InitCnnPacket();
	static void InitSynPacket();
	static UINT conect_scanthread(LPVOID);
	static UINT syn_scanthread(LPVOID);
	static void check_port(char *buffer);
	static UINT recv_packet_thread(LPVOID);
public:
	static u_short m_portnum;	///<端口数
	static u_short m_ncounter;
private:
	static CCriticalSection m_Sync;	

	static link_type m_scantype;
	static u_short m_threadnum;	///<启动线程数
	static u_short m_mainnum;	///<批次数
  	static u_short m_listCounter;

	static char	m_source_ip[16];
	static char	m_target_ip[16];
	static u_short m_target_port;
	static u_short m_start_port;
	static u_short m_end_port;
	static bool    m_isspecial;	

	static volatile SOCKET sock;	
	static SOCKET recv_sock;
	static SOCKADDR_IN connect_in;
	static SOCKADDR_IN synscan_in; 

	static volatile IP_HEADER  ipheader;  
	static volatile TCP_HEADER tcpheader;  
	static volatile PSD_HEADER psdheader;

	static CsmartkidDlg *m_pDlg;
};
