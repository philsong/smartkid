#pragma once
#include <vector>
using namespace::std;
class CsmartkidDlg;

class CDrdos
{
public:
	CDrdos(void);
	~CDrdos(void);
	void start_drdos(const vector<CString> &reflect_list);
private:
	void InitSynPacket();
	void InitIcmpPacket();
	static UINT  drdosthread(LPVOID);
	static UINT  syn_drdosthread(LPVOID);
	static UINT  icmp_drdosthread(LPVOID);
public:
	static u_short m_ncounter;
private:
	static vector<CString>  m_reflectlist;
	static CCriticalSection m_Sync;	
	static u_short m_threadnum;	///<启动线程数
	static u_short m_mainnum;	///<批次数
	static u_short m_listCounter;
	static link_type m_drdostype;
	
	static u_long	m_source_ip;
	static char	m_target_ip[16];
	static u_short	m_source_port; 
	static u_short  m_target_port;
	static u_long	m_seq_num;

	static volatile SOCKET		 sock;
	static volatile SOCKADDR_IN	 syn_in; 
	static volatile SOCKADDR_IN	 icmp_in; 

	static volatile IP_HEADER	 ipheader;  
	static volatile TCP_HEADER	 tcpheader;  
	static volatile PSD_HEADER	 psdheader;
	static volatile ICMP_HEADER	 icmpheader; 

	static CsmartkidDlg *m_pDlg;
};
