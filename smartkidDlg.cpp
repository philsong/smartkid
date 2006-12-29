// smartkidDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "smartkid.h"
#include "smartkidDlg.h"
#include "AboutCtrl.h"
#include "SnifferDlg.h"
#include "Login.h"
#include ".\smartkiddlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif



// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };
	

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
public:
	CAboutCtrl	m_AboutCtrl;
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	CString strCredits = "\t�ǻ�С�� SmartKid\n\n"
		"\rProgrammed by:\n"
		"���� songbohr@163.com\n\n"
		"\rSpecial thanks to:\n��Ѫ����\nFr.Qaker\nZV\nGxter\nzzzevazzz\nharambo\nand RedSword\n\n"
		"\rCopyright (c)2006 \n\r����Ƽ����޹�˾\n"
		"\rAll right reserved.\n\n"
		"Solutions at http://www.dream2fly.net\n";

	m_AboutCtrl.SetCredits(strCredits);
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_ABOUTCTRL, m_AboutCtrl);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	ON_WM_LBUTTONDOWN()
END_MESSAGE_MAP()



void CAboutDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	SendMessage( WM_CLOSE );

	CDialog::OnLButtonDown(nFlags, point);
}

bool g_stop=false;
// CsmartkidDlg �Ի���

CsmartkidDlg::CsmartkidDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CsmartkidDlg::IDD, pParent)
	, m_domain(_T(""))
	, m_isspecial(false)
	, m_startport(21)
	, m_endport(80)
	, m_drdosport(80)
	, m_ddosport(80)
	, m_reflectport(_T("179"))
	, m_scantype(_CONNECT)
	, m_ddostype(_SYN)
	, m_drdostype(_SYN)
	, m_threadnum(200)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}
CsmartkidDlg::~CsmartkidDlg()
{
}
void CsmartkidDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_URL, m_url);
	DDX_Control(pDX, IDC_EMAIL, m_email);

	DDX_Control(pDX, IDC_REFLECTLIST, m_reflectlist);
	DDX_IPAddress(pDX, IDC_REFLECTIP, m_reflectip);
	DDX_Text(pDX, IDC_TARGETDOMAIN, m_domain);
	DDX_Text(pDX, IDC_STARTPORT, m_startport);
	DDX_Text(pDX, IDC_ENDPORT, m_endport);
	DDX_Text(pDX, IDC_DRDOSPORT, m_drdosport);
	DDX_Text(pDX, IDC_DDOSPORT, m_ddosport);
	DDX_Text(pDX, IDC_REFLECTPORT, m_reflectport);
	DDX_Text(pDX, IDC_THREADNUM, m_threadnum);
	DDX_Control(pDX, IDC_IPPORT, m_listInfo);
	DDX_Control(pDX, IDC_ATTACKIPADDRESS, m_ctrtargetip);
	DDX_Control(pDX, IDC_LOCALIP, m_ctrlocalip);
	DDX_Control(pDX, IDC_REFLECTIP, m_ctrreflectip);
}

BEGIN_MESSAGE_MAP(CsmartkidDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_ABOUT, OnBnClickedAbout)
	ON_BN_CLICKED(IDC_ADDIP, OnBnClickedAddip)
	ON_BN_CLICKED(IDC_LOAD, OnBnClickedLoad)
	ON_BN_CLICKED(IDC_SAVE, OnBnClickedSave)
	ON_LBN_DBLCLK(IDC_REFLECTLIST, OnLbnDblclkReflectlist)
	ON_BN_CLICKED(IDC_SCANPORT, OnBnClickedScanport)
	ON_BN_CLICKED(IDC_DOMAINTOIP, OnBnClickedDomaintoip)
	ON_BN_CLICKED(IDC_CHECKALL, OnBnClickedCheckall)
	ON_BN_CLICKED(IDC_DDOSATTACK, OnBnClickedDdosattack)
	ON_BN_CLICKED(IDC_DRDOSATTACK, OnBnClickedDrdosattack)
	ON_BN_CLICKED(IDC_SYN, OnBnClickedSyn)
	ON_BN_CLICKED(IDC_DDOSSYN, OnBnClickedDdossyn)
	ON_BN_CLICKED(IDC_DDOSICMP, OnBnClickedDdosicmp)
	ON_BN_CLICKED(IDC_DRDOSSYN, OnBnClickedDrdossyn)
	ON_BN_CLICKED(IDC_DRDOSICMP, OnBnClickedDrdosicmp)
	ON_BN_CLICKED(IDC_UPDATE, OnBnClickedUpdate)
	ON_BN_CLICKED(IDC_PAUSE, OnBnClickedPause)
	ON_BN_CLICKED(IDC_SNIFFER, OnBnClickedSniffer)
	ON_WM_LBUTTONDOWN()
	ON_BN_CLICKED(IDC_README, OnBnClickedHelp)
	ON_BN_CLICKED(IDC_GODISCUSS, OnBnClickedGodiscuss)
END_MESSAGE_MAP()


// CsmartkidDlg ��Ϣ�������

BOOL CsmartkidDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��\������...\���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

#ifndef _DEBUG
	CLogin loginDlg;
	if(loginDlg.DoModal()==IDOK)
	{
		while(!(loginDlg.m_userid.CompareNoCase("dream2lfy" ) && loginDlg.m_serialno==78623269))
		{
			AfxMessageBox("����������������룡");
			if(loginDlg.DoModal()==IDCANCEL)
			{
				exit(-1);
			}
		}
	}
	else
	{
		exit(-1);
	}

	LoadingBmp();	
	
	OS_LEVEL os_level=get_win32_type();
	if(os_level==WIN_XP_SP2)
	{
		AfxMessageBox("ϵͳ��⵽���Ĳ���ϵͳ��WIN_XP_SP2��\n\n��ϵͳĿǰֻ��ʹ��connectɨ�蹦�ܣ�");
	}
#endif

	m_prog=(CProgressCtrl*)GetDlgItem(IDC_SCANPROGRESS);
	((CButton *)GetDlgItem(IDC_CHECKALL))->SetCheck(BST_CHECKED);
	m_isspecial=true;
	GetDlgItem(IDC_STARTPORT)->EnableWindow(FALSE);
	GetDlgItem(IDC_ENDPORT)->EnableWindow(FALSE);

	((CButton *)GetDlgItem(IDC_DDOSSYN))->SetCheck(BST_CHECKED);
	((CButton *)GetDlgItem(IDC_DRDOSSYN))->SetCheck(BST_CHECKED);

	//��ʼ����Ϣ�б��
	m_listInfo.InsertColumn(0,"IP",LVCFMT_LEFT,0,0);
	m_listInfo.InsertColumn(1,"PORT",LVCFMT_LEFT,0,0);
	m_listInfo.SetColumnWidth(0,100);
	m_listInfo.SetColumnWidth(1,60);


	///<��ȡ����IP��ַ
	m_localip="���ı���IP:";
	char localip[16];
	bool ret=getlocalip(localip);
	m_localip+=localip;
	m_ctrlocalip.SetWindowText(m_localip);	
	//��ʼ������IP

	//m_ctrtargetip.SetAddress(192,168,1,139);

	m_ctrreflectip.ClearAddress();

	m_url.SetURL(_T("http://www.dream2fly.net"));
	m_url.SetUnderline(FALSE);

	m_email.SetURL(_T("mailto:songbohr@163.com"));
	m_email.SetUnderline(FALSE);

	return TRUE;  // ���������˿ؼ��Ľ��㣬���򷵻� TRUE
}

void CsmartkidDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CsmartkidDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ��������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù����ʾ��
HCURSOR CsmartkidDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CsmartkidDlg::OnBnClickedAbout()
{
	CAboutDlg dlgAbout;
	dlgAbout.DoModal();
}

//ʵ�ֳ�����������  
void CsmartkidDlg::LoadingBmp(void)
{

	HDC hdc = ::GetDC(NULL);
	CDC *pDC = CDC::FromHandle(hdc);
	CBitmap *pBitmap = new CBitmap();
	if (pBitmap)
	{
		CBitmap *pOldBmp;
		BITMAP Bitmap;
		CDC dc;

		pBitmap->LoadBitmap(IDB_LOADING);
		dc.CreateCompatibleDC(pDC);
		pOldBmp = dc.SelectObject(pBitmap);
		pBitmap->GetObject(sizeof(Bitmap), &Bitmap);

		int cxScreen = GetSystemMetrics(SM_CXSCREEN);
		int cyScreen = GetSystemMetrics(SM_CYSCREEN);
		int x = (cxScreen-Bitmap.bmWidth)/2;
		int y = (cyScreen-Bitmap.bmHeight)/2;
		pDC->StretchBlt(x, y, Bitmap.bmWidth, Bitmap.bmHeight, &dc, 0 ,0, 
			Bitmap.bmWidth, Bitmap.bmHeight,SRCCOPY);
		dc.SelectObject(pOldBmp);
		dc.DeleteDC();
		pBitmap->DeleteObject();
		delete pBitmap;
	}
	::ReleaseDC(NULL, hdc);
	Sleep(1000);  
}

void CsmartkidDlg::OnBnClickedAddip()
{
	UpdateData(true);
	if(m_reflectip>0)
	{
		char* reflectip=new char[256];
		u_long reflect_ip=htonl(m_reflectip);
		TransformIp(reflectip,reflect_ip,true);
		strcat(reflectip,":");
		m_reflectlist.AddString(reflectip+m_reflectport);
		delete 	[]reflectip;
	}	
}

void CsmartkidDlg::OnBnClickedLoad()
{
	CFileDialog LoadDlg(true);
	LoadDlg.m_ofn.lpstrTitle = "���뷴��Դ��ַ";
	if (LoadDlg.DoModal()==IDOK)
	{
		CString strFileName=LoadDlg.GetPathName();
		CFile file(strFileName,CFile::modeRead);
		UINT len=static_cast<UINT>(file.GetLength());
		char *buf = new char[len];
		file.Read(buf,len);
		UINT i=0,j=0;
		while(i<len)
		{
			if ((buf[i]=='\r')&&(buf[i+1]=='\n'))
			{
				buf[i] = '\0';
				m_reflectlist.AddString(buf + j);
				j = i + 2;
				i+=2;
			}
			else if ((buf[i]!='\r')&&(buf[i]=='\n'))
			{
				buf[i] = '\0';
				m_reflectlist.AddString(buf + j);
				j = i + 1;
				++i;
			}
			else
			{
				++i;
			}
		}
		delete []buf;
		file.Close();
	}
}

void CsmartkidDlg::OnBnClickedSave()
{
	CFileDialog SaveDlg(false);
	SaveDlg.m_ofn.lpstrTitle = "��������Դ��ַ";
	if (SaveDlg.DoModal()==IDOK)
	{
		CString strFileName=SaveDlg.GetPathName ();
		CFile file(strFileName,CFile::modeWrite|CFile::modeCreate);
		CString strCurSel;
		CString strEnd="\r\n";
		for(int i=0;i<m_reflectlist.GetCount();i++)
		{
			m_reflectlist.GetText(i,strCurSel);
			strCurSel.Append(strEnd);
			file.Write (strCurSel,strCurSel.GetLength());
		}
		file.Close () ;
		MessageBox("�ɹ���������Դ��ַ�б�!");
	}
}

void CsmartkidDlg::OnLbnDblclkReflectlist()
{
	m_reflectlist.DeleteString (m_reflectlist.GetCurSel());
}

BOOL CsmartkidDlg::check_target_ip(void)
{
	if(m_ctrtargetip.IsBlank())
	{
		MessageBox("������IP��ַ",_T("����"),MB_ICONWARNING|MB_OK);
		return -1;
	}
	DWORD ip;

	if(m_ctrtargetip.GetAddress(ip)<4)
	{
		MessageBox("������������IP��ַ",_T("����"),MB_ICONWARNING|MB_OK);
		return -1;
	}

	m_ctrtargetip.GetWindowText(m_targetip);
	if(0==m_targetip.Compare("208.113.145.214"))
	{
		AfxMessageBox("��ż�Ĺ��߹�������վ���������!");
		return -1;
	}

	return 0;
}
void CsmartkidDlg::OnBnClickedScanport()
{
	if(-1==check_target_ip())
		return;	
	
	if(m_startport>m_endport)
	{
		MessageBox(_T("��ʼ�˿ڱ���С�ڵ��ڽ����˿ڣ�"));
		return;
	}

	m_listInfo.DeleteAllItems();
	UpdateData(true);

	m_portscan.start_scan();
}

void CsmartkidDlg::OnBnClickedDdosattack()
{
	if(-1==check_target_ip())
		return;
	UpdateData(true);
	m_ddos.start_ddos();
}

void CsmartkidDlg::OnBnClickedDrdosattack()
{
	UpdateData(true);
	if(-1==check_target_ip())
		return;

	if(m_reflectlist.GetCount()==0)
	{
		AfxMessageBox("����Դ�б���Ϊ��!");
		return;
	}

	std::vector<CString> reflectlist;
	CString strCurSel;
	for(int i=0;i<m_reflectlist.GetCount();i++)
	{
		m_reflectlist.GetText(i,strCurSel);
		reflectlist.push_back(strCurSel);		
	}

	m_drdos.start_drdos(reflectlist);
}

void CsmartkidDlg::OnBnClickedDomaintoip()
{
	UpdateData(true);

	if (m_domain.Find ("dream2fly.net",0)>=0) 
	{
		AfxMessageBox("��ż�Ĺ��߹�������վ���������!");
		return;
	}
	if (m_domain.Find ("eviloctal.com",0)>=0) 
	{
		AfxMessageBox("�˽��Ƶ�վ��ż���Ŷӣ���Ҳ��ɣ�������!");
		return;
	}

	hostent* pHostent = gethostbyname(m_domain.GetBuffer());
	if (pHostent == 0) 
	{
		AfxMessageBox("�����������Ч!");
		return;
	}			
	for (int nAdapter=0; pHostent->h_addr_list[nAdapter]; nAdapter++) 
	{
		char* ipaddr = NULL; 
		in_addr inaddr; 
		inaddr.s_addr=*(DWORD*)pHostent->h_addr_list[nAdapter]; 
		ipaddr= inet_ntoa(inaddr); 
		m_ctrtargetip.SetWindowText(ipaddr);
		break;
	}

	UpdateData(false);
}

void CsmartkidDlg::OnBnClickedCheckall()
{
	m_isspecial=m_isspecial?false:true;
	if(m_isspecial)
	{	
		GetDlgItem(IDC_STARTPORT)->EnableWindow(FALSE);
		GetDlgItem(IDC_ENDPORT)->EnableWindow(FALSE);
	}
	else
	{
		GetDlgItem(IDC_STARTPORT)->EnableWindow(TRUE);
		GetDlgItem(IDC_ENDPORT)->EnableWindow(TRUE);
	}
}
void CsmartkidDlg::OnBnClickedSyn()
{
	if(m_scantype==_CONNECT)
	{
		m_scantype=_SYN;
	}
	else
	{
		m_scantype=_CONNECT;
	}
}

void CsmartkidDlg::OnBnClickedDdossyn()
{
	m_ddostype=_SYN;
}

void CsmartkidDlg::OnBnClickedDdosicmp()
{
	m_ddostype=_ICMP;
}

void CsmartkidDlg::OnBnClickedDrdossyn()
{
	m_drdostype=_SYN;
}

void CsmartkidDlg::OnBnClickedDrdosicmp()
{
	m_drdostype=_ICMP;
}

void CsmartkidDlg::OnBnClickedUpdate()
{
	UINT ret=WinExec("update.exe smartkid 0.85 http://www.dream2fly.net/projects/smartkid_update.ini" ,SW_SHOW); 
	if(ERROR_FILE_NOT_FOUND==ret)
	{
		AfxMessageBox("�������������ʧ����ȷ��update.exe�Ƿ���ڣ�");
	}
}

void CsmartkidDlg::OnBnClickedHelp()
{
	WinExec("notepad.exe fag.txt",SW_SHOW); 
}

void CsmartkidDlg::OnBnClickedGodiscuss()
{
	CString url="http://www.dream2fly.net/forum/index.php";
	ShellExecute(NULL, _T("open"), url, NULL,NULL, SW_NORMAL);
}

void CsmartkidDlg::OnBnClickedPause()
{
	g_stop=true;
}


void CsmartkidDlg::OnBnClickedSniffer()
{
	CSnifferDlg snifferDlg;
	snifferDlg.DoModal();
}

void CsmartkidDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	//����϶�����
	SendMessage(WM_SYSCOMMAND,0xF012,0);

	CDialog::OnLButtonDown(nFlags, point);
}


