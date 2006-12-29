// SnifferDlg.cpp : 实现文件
//NDIS , DDK , pcaplib will add by songbo.

#include "stdafx.h"
#include "smartkid.h"
#include "SnifferDlg.h"

#include <winsock2.h>
#include "mstcpip.h"
#include "iphlpapi.h"
#pragma   comment   (lib,"Iphlpapi.lib")

// CSnifferDlg 对话框

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

	m_dataListCtrl.InsertColumn( 0, _T("协议"), LVCFMT_LEFT, 40);
	m_dataListCtrl.InsertColumn( 1, _T("源地址：端口"), LVCFMT_LEFT, 140);
	m_dataListCtrl.InsertColumn( 2, _T("目的地址：端口"), LVCFMT_LEFT, 140);
	m_dataListCtrl.InsertColumn( 3, _T("数据包大小"), LVCFMT_LEFT, 100);
	m_dataListCtrl.InsertColumn( 4, _T("时间"), LVCFMT_LEFT, 140);

	return TRUE;  // return TRUE unless you set the focus to a control
	// 异常: OCX 属性页应返回 FALSE
}
