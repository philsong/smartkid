#pragma once
#include "afxcmn.h"


// CSnifferDlg �Ի���

class CSnifferDlg : public CDialog
{
	DECLARE_DYNAMIC(CSnifferDlg)

public:
	CSnifferDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CSnifferDlg();

// �Ի�������
	enum { IDD = IDD_SNIFFER_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_dataListCtrl;
	virtual BOOL OnInitDialog();
};
