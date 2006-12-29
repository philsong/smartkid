#pragma once
#include "afxcmn.h"


// CSnifferDlg 对话框

class CSnifferDlg : public CDialog
{
	DECLARE_DYNAMIC(CSnifferDlg)

public:
	CSnifferDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CSnifferDlg();

// 对话框数据
	enum { IDD = IDD_SNIFFER_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_dataListCtrl;
	virtual BOOL OnInitDialog();
};
