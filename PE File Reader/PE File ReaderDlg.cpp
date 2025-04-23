#include "pch.h"
#include "framework.h"
#include "PE File Reader.h"
#include "PE File ReaderDlg.h"
#include "afxdialogex.h"
#include <atlconv.h> 

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_RESERVED  
#define IMAGE_DIRECTORY_ENTRY_RESERVED 16 
#endif

// Helper to format hex values
static CString Hex(DWORD v, int width = 4) {
    CString s;
    s.Format(_T("%0*X"), width, v);
    return s;
}

BEGIN_MESSAGE_MAP(CPEFileReaderDlg, CDialogEx)
    ON_WM_DESTROY()
    ON_WM_DROPFILES()
    ON_BN_CLICKED(IDC_BUTTON1, &CPEFileReaderDlg::OnBnClickedButton1)
    ON_CBN_SELCHANGE(IDC_COMBO1, &CPEFileReaderDlg::OnCbnSelchangeCombo1)
END_MESSAGE_MAP()

CPEFileReaderDlg::CPEFileReaderDlg(CWnd* pParent)
    : CDialogEx(IDD_PE_FILE_READER_DIALOG, pParent)
{
}

BOOL CPEFileReaderDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    DragAcceptFiles(TRUE);

    // m_editFilePath.SubclassDlgItem(IDC_EDIT1, this);
    // m_buttonLoad.SubclassDlgItem(IDC_BUTTON1, this);
    // m_comboSections.SubclassDlgItem(IDC_COMBO1, this);
    // m_listOutput.SubclassDlgItem(IDC_LIST1, this);
    UpdateData(FALSE);

    static const TCHAR* sections[] = {
        _T("Dos Header"),
        _T("Nt Headers"),
        _T("File Header"),
        _T("Optional Header"),
        _T("Data Directories"),
        _T("Section Headers"),
        _T("Import Directory"),
        _T("Relocation Directory"),
        _T("Debug Directory")
    };
    for (auto& s : sections)
        m_comboSections.AddString(s);
    m_comboSections.SetCurSel(0);

    return TRUE;
}

void CPEFileReaderDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_EDIT1, m_editFilePath);
    DDX_Control(pDX, IDC_BUTTON1, m_buttonLoad);
    DDX_Control(pDX, IDC_COMBO1, m_comboSections);
    DDX_Control(pDX, IDC_LIST1, m_listOutput);
}

bool CPEFileReaderDlg::LoadFile(const CString& path)
{
    // free previous
    if (m_fileData) {
        HeapFree(GetProcessHeap(), 0, m_fileData);
        m_fileData = nullptr;
    }

    // open
    HANDLE h = CreateFileW(path,
        GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        AfxMessageBox(_T("Failed to open file."));
        return false;
    }

    // size + alloc
    m_fileSize = GetFileSize(h, nullptr);
    m_fileData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, m_fileSize);
    if (!m_fileData) {
        CloseHandle(h);
        AfxMessageBox(_T("Out of memory."));
        return false;
    }

    // read
    DWORD readBytes = 0;
    if (!ReadFile(h, m_fileData, m_fileSize, &readBytes, nullptr) ||
        readBytes != m_fileSize) {
        CloseHandle(h);
        AfxMessageBox(_T("Failed to read file."));
        return false;
    }
    CloseHandle(h);

    // parse
    m_pDos = (PIMAGE_DOS_HEADER)m_fileData;
    if (m_pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        AfxMessageBox(_T("Invalid DOS signature."));
        return false;
    }
    m_pNt = (PIMAGE_NT_HEADERS)(m_fileData + m_pDos->e_lfanew);
    if (m_pNt->Signature != IMAGE_NT_SIGNATURE) {
        AfxMessageBox(_T("Invalid NT signature."));
        return false;
    }

    return true;
}

// Load button
void CPEFileReaderDlg::OnBnClickedButton1()
{
    CString path;
    m_editFilePath.GetWindowText(path);
    if (path.IsEmpty()) {
        AfxMessageBox(_T("Please enter or drop a file path."));
        return;
    }

    if (!LoadFile(path))
        return;

    m_listOutput.ResetContent();
    m_listOutput.AddString(_T("Loaded file: ") + path);
}

// Drag & drop
void CPEFileReaderDlg::OnDropFiles(HDROP hDropInfo)
{
    TCHAR path[MAX_PATH]{};
    DragQueryFile(hDropInfo, 0, path, MAX_PATH);
    DragFinish(hDropInfo);

    m_editFilePath.SetWindowText(path);
    if (!LoadFile(path))
        return;

    m_listOutput.ResetContent();
    m_listOutput.AddString(_T("Dropped file: ") + CString(path));
}

void CPEFileReaderDlg::OnCbnSelchangeCombo1()
{
    m_listOutput.ResetContent();
    int idx = m_comboSections.GetCurSel();
    switch (idx)
    {
    case 0:
        //DOS Header
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("DOS Header:"));
        m_listOutput.AddString(_T("e_magic(Magic number): ") + Hex(m_pDos->e_magic, 8));
        m_listOutput.AddString(_T("e_cblp(Bytes on last page of file): ") + Hex(m_pDos->e_cblp, 8));
        m_listOutput.AddString(_T("e_cp(Pages in file): ") + Hex(m_pDos->e_cp, 8));
        m_listOutput.AddString(_T("e_crlc(Relocations): ") + Hex(m_pDos->e_crlc, 8));
        m_listOutput.AddString(_T("e_cparhdr(Size of header in paragraphs): ") + Hex(m_pDos->e_cparhdr, 8));
        m_listOutput.AddString(_T("e_minalloc(Minimum extra paragraphs needed): ") + Hex(m_pDos->e_minalloc, 8));
        m_listOutput.AddString(_T("e_maxalloc(Maximum extra paragraphs needed): ") + Hex(m_pDos->e_maxalloc, 8));
        m_listOutput.AddString(_T("e_ss(Initial (relative) SS value): ") + Hex(m_pDos->e_ss, 8));
        m_listOutput.AddString(_T("e_sp(Initial SP value): ") + Hex(m_pDos->e_sp, 8));
        m_listOutput.AddString(_T("e_csum(Checksum): ") + Hex(m_pDos->e_csum, 8));
        m_listOutput.AddString(_T("e_ip(Initial IP value): ") + Hex(m_pDos->e_ip, 8));
        m_listOutput.AddString(_T("e_cs(Initial (relative) CS value): ") + Hex(m_pDos->e_cs, 8));
        m_listOutput.AddString(_T("e_lfarlc(File address of relocation table): ") + Hex(m_pDos->e_lfarlc, 8));
        m_listOutput.AddString(_T("e_ovno(Overlay number): ") + Hex(m_pDos->e_ovno, 8));
        m_listOutput.AddString(_T("e_oemid(OEM identifier): ") + Hex(m_pDos->e_oemid, 8));
        m_listOutput.AddString(_T("e_oeminfo(OEM information): ") + Hex(m_pDos->e_oeminfo, 8));
        m_listOutput.AddString(_T("e_lfanew(File address of new exe header): ") + Hex(m_pDos->e_lfanew, 8));

        break;

    case 1:
        //NT Headers
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("Signature: ") + Hex(m_pNt->Signature, 8));
        m_listOutput.AddString(_T("NumberOfSections: ") + Hex(m_pNt->FileHeader.NumberOfSections));
        break;

    case 2:
        //File Header
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("Machine: ") + Hex(m_pNt->FileHeader.Machine));
        m_listOutput.AddString(_T("Number of Sections: ") + Hex(m_pNt->FileHeader.NumberOfSections));
        m_listOutput.AddString(_T("Time Stamp: ") + Hex(m_pNt->FileHeader.TimeDateStamp));
        m_listOutput.AddString(_T("Pointer To Symbol Table: ") + Hex(m_pNt->FileHeader.PointerToSymbolTable));
        m_listOutput.AddString(_T("Number Of Symbols: ") + Hex(m_pNt->FileHeader.NumberOfSymbols));
        m_listOutput.AddString(_T("Size Of Optional Header: ") + Hex(m_pNt->FileHeader.SizeOfOptionalHeader));
        m_listOutput.AddString(_T("Characteristics: ") + Hex(m_pNt->FileHeader.Characteristics));
        break;
    case 3:
        //Optional Header
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("Magic: ") + Hex(m_pNt->OptionalHeader.Magic));
        m_listOutput.AddString(_T("Major Linker Version: ") + Hex(m_pNt->OptionalHeader.MajorLinkerVersion));
        m_listOutput.AddString(_T("Minor Linker Version: ") + Hex(m_pNt->OptionalHeader.MinorLinkerVersion));
        m_listOutput.AddString(_T("Size Of Code: ") + Hex(m_pNt->OptionalHeader.SizeOfCode));
        m_listOutput.AddString(_T("Size Of Initialized Data: ") + Hex(m_pNt->OptionalHeader.SizeOfInitializedData));
        m_listOutput.AddString(_T("Size Of Uninitialized Data: ") + Hex(m_pNt->OptionalHeader.SizeOfUninitializedData));
        m_listOutput.AddString(_T("Address Of Entry Point: ") + Hex(m_pNt->OptionalHeader.AddressOfEntryPoint));
        m_listOutput.AddString(_T("Base Of Code: ") + Hex(m_pNt->OptionalHeader.BaseOfCode));
        m_listOutput.AddString(_T("Image Base: ") + Hex(m_pNt->OptionalHeader.ImageBase));
        m_listOutput.AddString(_T("Section Alignment: ") + Hex(m_pNt->OptionalHeader.SectionAlignment));
        m_listOutput.AddString(_T("File Alignment: ") + Hex(m_pNt->OptionalHeader.FileAlignment));
        m_listOutput.AddString(_T("Major Operating System Version: ") + Hex(m_pNt->OptionalHeader.MajorOperatingSystemVersion));
        m_listOutput.AddString(_T("Minor Operating System Version: ") + Hex(m_pNt->OptionalHeader.MinorOperatingSystemVersion));
        m_listOutput.AddString(_T("Major Image Version: ") + Hex(m_pNt->OptionalHeader.MajorImageVersion));
        m_listOutput.AddString(_T("Minor Image Version: ") + Hex(m_pNt->OptionalHeader.MinorImageVersion));
        m_listOutput.AddString(_T("Major Subsystem Version: ") + Hex(m_pNt->OptionalHeader.MajorSubsystemVersion));
        m_listOutput.AddString(_T("Minor Subsystem Version: ") + Hex(m_pNt->OptionalHeader.MinorSubsystemVersion));
        m_listOutput.AddString(_T("Win32 Version Value: ") + Hex(m_pNt->OptionalHeader.Win32VersionValue));
        m_listOutput.AddString(_T("Size Of Image: ") + Hex(m_pNt->OptionalHeader.SizeOfImage));
        m_listOutput.AddString(_T("Size Of Headers: ") + Hex(m_pNt->OptionalHeader.SizeOfHeaders));
        m_listOutput.AddString(_T("CheckSum: ") + Hex(m_pNt->OptionalHeader.CheckSum));
        m_listOutput.AddString(_T("Subsystem: ") + Hex(m_pNt->OptionalHeader.Subsystem));
        m_listOutput.AddString(_T("Dll Characteristics: ") + Hex(m_pNt->OptionalHeader.DllCharacteristics));
        m_listOutput.AddString(_T("Size Of Stack Reserve: ") + Hex(m_pNt->OptionalHeader.SizeOfStackReserve));
        m_listOutput.AddString(_T("Size Of Stack Commit: ") + Hex(m_pNt->OptionalHeader.SizeOfStackCommit));
        m_listOutput.AddString(_T("Size Of Heap Reserve: ") + Hex(m_pNt->OptionalHeader.SizeOfHeapReserve));
        m_listOutput.AddString(_T("Size Of Heap Commit: ") + Hex(m_pNt->OptionalHeader.SizeOfHeapCommit));
        m_listOutput.AddString(_T("Loader Flags: ") + Hex(m_pNt->OptionalHeader.LoaderFlags));
        m_listOutput.AddString(_T("Number Of Rva And Sizes: ") + Hex(m_pNt->OptionalHeader.NumberOfRvaAndSizes));
        break;
    case 4:
        //Data Directories
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("Export Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
        m_listOutput.AddString(_T("Import Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
        m_listOutput.AddString(_T("Resource Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress));
        m_listOutput.AddString(_T("Exception Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));
        m_listOutput.AddString(_T("Security Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress));
        m_listOutput.AddString(_T("Base Relocation Table: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
        m_listOutput.AddString(_T("Debug Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
        m_listOutput.AddString(_T("Architecture Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress));
        m_listOutput.AddString(_T("Global Pointer Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress));
        m_listOutput.AddString(_T("TLS Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
        m_listOutput.AddString(_T("Load Configuration Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress));
        m_listOutput.AddString(_T("Bound Import Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress));
        m_listOutput.AddString(_T("Import Address Table: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
        m_listOutput.AddString(_T("Delay Import Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress));
        m_listOutput.AddString(_T("COM Descriptor Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress));
        m_listOutput.AddString(_T("Reserved Directory: ") + Hex(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESERVED].VirtualAddress));
        break;
    case 5:
        //Section Headers
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("Section Headers:"));
        for (int i = 0; i < m_pNt->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNt) + i;
            CString sectionName = CString((char*)pSectionHeader->Name);
            m_listOutput.AddString(_T("Section Name: ") + sectionName);
            m_listOutput.AddString(_T("Virtual Size: ") + Hex(pSectionHeader->Misc.VirtualSize));
            m_listOutput.AddString(_T("Virtual Address: ") + Hex(pSectionHeader->VirtualAddress));
            m_listOutput.AddString(_T("Size Of Raw Data: ") + Hex(pSectionHeader->SizeOfRawData));
            m_listOutput.AddString(_T("Pointer To Raw Data: ") + Hex(pSectionHeader->PointerToRawData));
            m_listOutput.AddString(_T("Pointer To Relocations: ") + Hex(pSectionHeader->PointerToRelocations));
            m_listOutput.AddString(_T("Pointer To Linenumbers: ") + Hex(pSectionHeader->PointerToLinenumbers));
            m_listOutput.AddString(_T("Number Of Relocations: ") + Hex(pSectionHeader->NumberOfRelocations));
            m_listOutput.AddString(_T("Number Of Linenumbers: ") + Hex(pSectionHeader->NumberOfLinenumbers));
            m_listOutput.AddString(_T("Characteristics: ") + Hex(pSectionHeader->Characteristics));
        }
        break;
    case 6: {
		//Import Directory
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("Import Directory:"));

        DWORD importVA = m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (importVA == 0 || importSize == 0) {
            m_listOutput.AddString(_T("No Import Directory available."));
            break;
        }

        if (importVA > m_fileSize || importVA + sizeof(IMAGE_IMPORT_DESCRIPTOR) > m_fileSize) {
            m_listOutput.AddString(_T("Invalid Import Directory address."));
            break;
        }

        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(m_fileData + importVA);

        for (int i = 0; ; i++) {
            IMAGE_IMPORT_DESCRIPTOR& desc = pImportDesc[i];
            if (desc.Name == 0)
                break;

            if (desc.Name > m_fileSize) {
                m_listOutput.AddString(_T("Invalid DLL Name address."));
                break;
            }

            char* ansiStr = (char*)(m_fileData + desc.Name);
            CString dllName = CA2W(ansiStr);
            m_listOutput.AddString(_T("DLL Name: ") + dllName);
            m_listOutput.AddString(_T("Time Stamp: ") + Hex(desc.TimeDateStamp));
            m_listOutput.AddString(_T("Forwarder Chain: ") + Hex(desc.ForwarderChain));
            m_listOutput.AddString(_T("Characteristics: ") + Hex(desc.Characteristics));

            DWORD descriptorSize = sizeof(IMAGE_IMPORT_DESCRIPTOR);
            CString rvaStr = Hex(importVA + i * descriptorSize);
            m_listOutput.AddString(_T("Import Descriptor RVA: ") + rvaStr);
            m_listOutput.AddString(_T("Import Lookup Table: ") + Hex(desc.OriginalFirstThunk));
            m_listOutput.AddString(_T("Import Address Table: ") + Hex(desc.FirstThunk));
            m_listOutput.AddString(_T("Import Name Table: ") + Hex(desc.FirstThunk));
        }

        break;
    }

    case 7: {
        //Relocation Directory
        m_listOutput.ResetContent();
        m_listOutput.AddString(_T("Relocation Directory:"));
        PIMAGE_BASE_RELOCATION pRelocDesc = (PIMAGE_BASE_RELOCATION)(m_fileData + m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        for (int i = 0; pRelocDesc[i].VirtualAddress != 0; i++) {
            m_listOutput.AddString(_T("Virtual Address: ") + Hex(pRelocDesc[i].VirtualAddress));
            m_listOutput.AddString(_T("Size Of Block: ") + Hex(pRelocDesc[i].SizeOfBlock));
            DWORD relocBlockRVA = m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            DWORD descriptorSize = sizeof(IMAGE_BASE_RELOCATION);
            CString rvaStr = Hex(relocBlockRVA + i * descriptorSize);
            m_listOutput.AddString(_T("Relocation Block RVA: ") + rvaStr);
        }
		break;
    }
    case 8: {
		//Debug Directory
		m_listOutput.ResetContent();

		m_listOutput.AddString(_T("Debug Directory:"));
		PIMAGE_DEBUG_DIRECTORY pDebugDesc = (PIMAGE_DEBUG_DIRECTORY)(m_fileData + m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
        for (int i = 0; i < m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
            m_listOutput.AddString(_T("Characteristics: ") + Hex(pDebugDesc[i].Characteristics));
            m_listOutput.AddString(_T("Time Date Stamp: ") + Hex(pDebugDesc[i].TimeDateStamp));
            m_listOutput.AddString(_T("Major Version: ") + Hex(pDebugDesc[i].MajorVersion));
            m_listOutput.AddString(_T("Minor Version: ") + Hex(pDebugDesc[i].MinorVersion));
            m_listOutput.AddString(_T("Type: ") + Hex(pDebugDesc[i].Type));
            m_listOutput.AddString(_T("Size Of Data: ") + Hex(pDebugDesc[i].SizeOfData));
            m_listOutput.AddString(_T("Address Of Raw Data: ") + Hex(pDebugDesc[i].AddressOfRawData));
            m_listOutput.AddString(_T("Pointer To Raw Data: ") + Hex(pDebugDesc[i].PointerToRawData));
        }
        break;
    }

    default:
        m_listOutput.AddString(_T("[Not implemented]"));
        break;
    }
}


// Cleanup
void CPEFileReaderDlg::OnDestroy()
{
    CDialogEx::OnDestroy();
    if (m_fileData) {
        HeapFree(GetProcessHeap(), 0, m_fileData);
        m_fileData = nullptr;
    }
}
