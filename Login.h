#pragma once



// CLogin ������ͼ

class CLogin : public CDialog
{
	DECLARE_DYNCREATE(CLogin)

public:
	CLogin();           // ��̬������ʹ�õ��ܱ����Ĺ��캯��
	virtual ~CLogin();

public:
	enum { IDD = IDD_LOGIN };
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CString m_userid;
	long m_serialno;
};


