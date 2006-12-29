#pragma once



// CLogin 窗体视图

class CLogin : public CDialog
{
	DECLARE_DYNCREATE(CLogin)

public:
	CLogin();           // 动态创建所使用的受保护的构造函数
	virtual ~CLogin();

public:
	enum { IDD = IDD_LOGIN };
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CString m_userid;
	long m_serialno;
};


