
// PE File Reader.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'pch.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CPEFileReaderApp:
// See PE File Reader.cpp for the implementation of this class
//

class CPEFileReaderApp : public CWinApp
{
public:
	CPEFileReaderApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation
private:
	PIMAGE_DOS_HEADER m_pDos;     // after Load: points into your mapped file
	PIMAGE_NT_HEADERS m_pNt;

	DECLARE_MESSAGE_MAP()
};

extern CPEFileReaderApp theApp;
