// SnifferDlg.cpp : ʵ���ļ�
//NDIS , DDK , pcaplib will add by songbo.

#include "stdafx.h"
#include "smartkid.h"
#include "SnifferDlg.h"

#include <winsock2.h>
#include "mstcpip.h"
#include "iphlpapi.h"
#pragma   comment   (lib,"Iphlpapi.lib")

// CSnifferDlg �Ի���

IMPLEMENT_DYNAMIC(CSnifferDlg, CDialog)
CSnifferDlg::CSnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSnifferDlg::IDD, pParent)
{
}

CSnifferDlg::~CSnifferDlg()
{
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_SNIFFER_LIST, m_dataListCtrl);
}


BEGIN_MESSAGE_MAP(CSnifferDlg, CDialog)
END_MESSAGE_MAP()

BOOL CSnifferDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	SetWindowText("Sniffer");

	m_dataListCtrl.InsertColumn( 0, _T("Э��"), LVCFMT_LEFT, 40);
	m_dataListCtrl.InsertColumn( 1, _T("Դ��ַ���˿�"), LVCFMT_LEFT, 140);
	m_dataListCtrl.InsertColumn( 2, _T("Ŀ�ĵ�ַ���˿�"), LVCFMT_LEFT, 140);
	m_dataListCtrl.InsertColumn( 3, _T("���ݰ���С"), LVCFMT_LEFT, 100);
	m_dataListCtrl.InsertColumn( 4, _T("ʱ��"), LVCFMT_LEFT, 140);

	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣: OCX ����ҳӦ���� FALSE
}
