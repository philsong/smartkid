#include "StdAfx.h"
#include "socksupport.h"

CSockSupport::CSockSupport(bool bAuto)
{
	m_bSupported = false;

	if(bAuto)
		Init();
}

CSockSupport::~CSockSupport(void)
{
	if(m_bSupported)
		Uninit();
}

int CSockSupport::Init()
{
	WSADATA wsaData;
	if (WSAStartup(WINSOCK_VERSION, &wsaData) != 0)
	{
		return WSAGetLastError();
	}

	//Confirm that the WinSock DLL supports 2.0
	if(LOBYTE(wsaData.wVersion)!=LOBYTE(WINSOCK_VERSION) ||
		HIBYTE(wsaData.wVersion)!=HIBYTE(WINSOCK_VERSION) )
	{
		WSACleanup();
		return WSAGetLastError();
	}

	m_bSupported = true;
	return 0;
}

int CSockSupport::Uninit()
{
	WSACleanup();
	return 0;
}

bool CSockSupport::IsSupported()
{
	return m_bSupported;
}

