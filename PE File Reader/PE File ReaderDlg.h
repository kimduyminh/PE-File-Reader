#pragma once
#include "afxwin.h"
#include <windows.h>
#include <winnt.h>

class CPEFileReaderDlg : public CDialogEx
{
public:
    CPEFileReaderDlg(CWnd* pParent = nullptr);

    enum { IDD = IDD_PE_FILE_READER_DIALOG };

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();
    afx_msg void OnDestroy();
    DECLARE_MESSAGE_MAP()

private:
    // PE Data
    BYTE* m_fileData = nullptr;
    DWORD                m_fileSize = 0;
    PIMAGE_DOS_HEADER    m_pDos = nullptr;
    PIMAGE_NT_HEADERS    m_pNt = nullptr;

	//UI Elements
    bool LoadFile(const CString& path);
    CEdit     m_editFilePath;    
    CButton   m_buttonLoad;      
    CComboBox m_comboSections;   
    CListBox  m_listOutput;      

    //Event Handlers 
    afx_msg void OnDropFiles(HDROP hDropInfo);
    afx_msg void OnBnClickedButton1();
    afx_msg void OnCbnSelchangeCombo1();
};
