// Login.cpp : 实现文件
//

#include "stdafx.h"
#include "smartkid.h"
#include "Login.h"


// CLogin

IMPLEMENT_DYNCREATE(CLogin, CDialog)

CLogin::CLogin()
	: CDialog(CLogin::IDD)
	, m_userid(_T("dream2fly"))
	, m_serialno(78623269)
{
}

CLogin::~CLogin()
{
}

void CLogin::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_LOGINNAME, m_userid);
	DDX_Text(pDX, IDC_PASSWORD, m_serialno);
}

BEGIN_MESSAGE_MAP(CLogin, CDialog)
END_MESSAGE_MAP()


// CLogin 诊断

#ifdef _DEBUG
void CLogin::AssertValid() const
{
	CDialog::AssertValid();
}

void CLogin::Dump(CDumpContext& dc) const
{
	CDialog::Dump(dc);
}
#endif //_DEBUG


// CLogin 消息处理程序
