// smartkidDlg.h : 头文件
//

#pragma once
#include "resource.h"

#include "hyperlink.h"
#include "SockSupport.h"
#include "portscan.h"
#include "ddos.h"
#include "drdos.h"
#include "afxcmn.h"
#include "afxwin.h"

static CSockSupport g_sockSpt;

// CsmartkidDlg 对话框
class CsmartkidDlg : public CDialog
{
	// 构造
public:
	CsmartkidDlg(CWnd* pParent = NULL);	// 标准构造函数
	~CsmartkidDlg();
	// 对话框数据
	enum { IDD = IDD_SMARTKID_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

	// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
	BOOL check_target_ip(void);
	afx_msg void OnBnClickedAbout();
	afx_msg void OnBnClickedAddip();
	afx_msg void OnBnClickedLoad();
	afx_msg void OnBnClickedSave();
	afx_msg void OnLbnDblclkReflectlist();
	afx_msg void OnBnClickedScanport();
	afx_msg void OnBnClickedDdosattack();
	afx_msg void OnBnClickedDrdosattack();
	afx_msg void OnBnClickedDomaintoip();
	afx_msg void OnBnClickedCheckall();
public:
	CProgressCtrl *m_prog;	
	CListCtrl m_listInfo;

	CListBox m_reflectlist;
	bool m_isspecial;
	CString m_domain;
	CString m_localip;
	CIPAddressCtrl m_ctrtargetip;	
	CString m_targetip;
	CStatic m_ctrlocalip;
	CIPAddressCtrl m_ctrreflectip;
	DWORD m_reflectip;	
	CString m_reflectport;
	int m_drdosport;
	int m_ddosport;
	int m_startport;
	int m_endport;
	CPortScan m_portscan;
	CDdos	  m_ddos;
	CDrdos	  m_drdos;
	link_type m_scantype;
	link_type m_ddostype;
	link_type m_drdostype;
	int m_threadnum;

	CHyperLink m_url;
	CHyperLink m_email;
public:
	void LoadingBmp(void);
	afx_msg void OnBnClickedSyn();
	afx_msg void OnBnClickedDdossyn();
	afx_msg void OnBnClickedDdosicmp();
	afx_msg void OnBnClickedDrdossyn();
	afx_msg void OnBnClickedDrdosicmp();
	afx_msg void OnEnChangeThreadnum();
	afx_msg void OnBnClickedUpdate();
	afx_msg void OnBnClickedPause();
	afx_msg void OnBnClickedSniffer();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnBnClickedHelp();
	afx_msg void OnBnClickedGodiscuss();
};
extern bool g_stop;