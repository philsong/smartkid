// smartkid.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error �ڰ������� PCH �Ĵ��ļ�֮ǰ������stdafx.h��
#endif

#include "resource.h"		// ������


// CsmartkidApp:
// �йش����ʵ�֣������ smartkid.cpp
//

class CsmartkidApp : public CWinApp
{
public:
	CsmartkidApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CsmartkidApp theApp;
