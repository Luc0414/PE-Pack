#include "PeInfo.h"
#include <fstream>

using namespace std;

// RAII�������Զ�������Դ���ļ���������ͷ�
class ScopedFile {
public:
	ScopedFile(const char* path, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::binary) : stream_(path, mode)
	{}

	// �����������Զ��ر��ļ����
	~ScopedFile() {
		if (stream_.is_open()) {
			stream_.close();
		}
	}

	// & �� C++ �е������������ ����������֮��Ķ�������á�
	std::ifstream& get() { return stream_; }

public:
	std::ifstream stream_;
};

// ��ȡ�ļ���С
DWORD PEInfo::GetFileSize(const char* path) {
	ScopedFile fin(path);
	// �ļ���ʧ��
	if (!fin.get().good()) return 0;
	// �ƶ����ļ���β
	fin.get().seekg(0, std::ios::end);
	// ���ص�ǰ�ļ�ָ���λ�ã����ļ���С
	return static_cast<DWORD>(fin.get().tellg());
}

// ��ȡ�ļ�����
DWORD PEInfo::readFile(const char* path, LPBYTE pFileBuf, DWORD size) {
	ScopedFile fin(path);
	// �ļ���ʧ�ܻ��ߴ����ָ��Ϊ��ָ��
	if (!fin.get().good() || !pFileBuf) return 0;
	// �ƶ����ļ���β
	fin.get().seekg(0, std::ios::end);
	// ��ȡ�ļ���С static_cast C++ת�������
	const DWORD fsize = static_cast<DWORD>(fin.get().tellg());
	// �ƶ����ļ���ͷ
	fin.get().seekg(0, std::ios::beg);
	if (size == 0 || fsize < size) size = fsize;
	// ��ȡ�ļ����ݵ�ָ�������� reinterpret_cast C++ת������� ��һ�����͵�ָ��ת��Ϊ��һ�����͵�ָ��
	fin.get().read(reinterpret_cast<char*>(pFileBuf), size);
	// ����ʵ�ʶ�ȡ���ֽ���
	return size;
}

// ��ָ��·����ȡPE�ļ������ص�ָ���ڴ��ַ�У�����ѡ���Ƿ����ڴ�������������
DWORD PEInfo::loadPeFile(const char* path, LPBYTE pPeBuf, DWORD* FileBufSize, bool bMemAlign, LPBYTE pOverlayBuf, DWORD* OverlayBufSize) {
	// ������ص����ڴ��ַΪ�գ�ֱ�ӷ���0
	if (pPeBuf == NULL) return 0;
	DWORD loadsize = 0;
	DWORD filesize = GetFileSize(path);
	// �����ļ�������
	LPBYTE buf = new BYTE[filesize];
	// ��ȡPE�ļ�����������
	if (readFile(path, buf, 0) <= 0) return 0;
	// �ж�PE�ļ��Ƿ���Ч
	if (isPe(buf) > 0) {
		// ��ȡPEͷ�ͽڱ�ͷ
		PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(buf);
		PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(buf);
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;
		DWORD last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		// ����������ڴ�������������
		if (bMemAlign == false) {
			// ֱ�ӽ�PE�ļ����ݸ��Ƶ�Ŀ���ڴ��ַ��
			memcpy(pPeBuf, buf, filesize);
			// ����ļ���������С��Ϊ�գ�������ֵΪ�ļ���С
			if (FileBufSize != NULL) *FileBufSize = filesize;
			// �������overlay���ݣ������ȡ��ָ����������
			if (last_faddr < filesize) {
				memcpy(pOverlayBuf, buf + last_faddr, filesize - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
			}
			loadsize = filesize;
		}
		else {
			// �����ڴ�������������
			// �Ƚ�Ŀ���ڴ��ַ����
			memset(pPeBuf, 0, memsize);
			loadsize = memsize;
			// ����PE�ļ�ͷ��Ŀ���ڴ��ַ��
			memcpy(pPeBuf, buf, pNtHeader->OptionalHeader.SizeOfHeaders);
			// ����ÿ���ڵ����ݵ�Ŀ���ڴ��ַ��
			for (int i = 0; i < sec_num; i++) {
				memcpy(pPeBuf + pSecHeader[i].VirtualAddress, buf + pSecHeader[i].PointerToRawData, pSecHeader[i].SizeOfRawData);
			}
			// �������overlay���ݣ������ȡ��ָ����������
			if (last_faddr < filesize) {
				memcpy(pOverlayBuf, buf + last_faddr, filesize - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
				loadsize += filesize - last_faddr;
			}
		}
		// �ͷ��ڴ�
		delete[] buf;
	}

	return loadsize;

}
// �жϸ������ļ��Ƿ�ΪPE��ʽ
int PEInfo::isPe(const char* path) {
	BYTE buf[PEHBUF_SIZE];
	// ��ȡ�ļ�ʧ�ܣ�����-3
	if (readFile(path, (LPBYTE)buf, PEHBUF_SIZE) == 0) return -3;
	// ����isPe(LPBYTE pPeBuf)�����ж��ļ��Ƿ�ΪPE��ʽ
	return isPe((LPBYTE)buf);
}

// �жϸ����Ķ����ƻ������Ƿ�ΪPE��ʽ
int PEInfo::isPe(LPBYTE pPeBuf) {
	// ��ȡPE�ļ���DOSͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPeBuf;
	// �ж��Ƿ�ΪMZͷ
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return -1;
	// ��ȡPE�ļ���NTͷ
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pPeBuf);
	// �ж��Ƿ�ΪPEͷ
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return -2;
	// ����PEͷ��ħ��
	return pNtHeader->OptionalHeader.Magic;
}

// ��ȡ���������ƻ�������NTͷָ��
PIMAGE_NT_HEADERS PEInfo::GetNtHeader(LPBYTE pPeBuf) {
	// ��ȡPE�ļ���DOSͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPeBuf;
	// ��ȡPE�ļ���NTͷָ��
	return (PIMAGE_NT_HEADERS)(pPeBuf + pDosHeader->e_lfanew);
}



// ��ȡ���������ƻ������Ľ���ͷָ��
PIMAGE_SECTION_HEADER PEInfo::GetSectionHeader(LPBYTE pPeBuf) {
	// ��ȡPE�ļ���NTͷ
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pPeBuf);
	// ��ȡPE�ļ��Ľ���ͷָ��
	return (PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader + sizeof(IMAGE_NT_HEADERS));
}

// ��ȡ���������ƻ��������ļ�ͷ
PIMAGE_FILE_HEADER PEInfo::GetFileHeader(LPBYTE pPeBuf) {
	return &GetNtHeader(pPeBuf)->FileHeader;
}

// ��ȡ���������ƻ������Ŀ�ѡͷ
PIMAGE_OPTIONAL_HEADER PEInfo::GetOptionalHeader(LPBYTE pPeBuf) {
	return &GetNtHeader(pPeBuf)->OptionalHeader;
}

// ��ȡ���������ƻ�����������Ŀ¼
PIMAGE_DATA_DIRECTORY PEInfo::GetImageDataDirectory(LPBYTE pPeBuf) {
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	return pOptionalHeader->DataDirectory;
}


PIMAGE_IMPORT_DESCRIPTOR PEInfo::getImportDescriptor(LPBYTE pPeBuf, bool bMemAlign = true) {
	// ��ȡ����Ŀ¼
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = GetImageDataDirectory(pPeBuf);
	// ��ȡ�������������RVA
	DWORD RVA = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	// �����ڴ�����־��������������������ļ��е�ƫ����
	DWORD offset = bMemAlign ? RVA : rva2faddr(pPeBuf, RVA);
	// ���ص�����������ָ��
	return (PIMAGE_IMPORT_DESCRIPTOR)(pPeBuf + offset);
}
PIMAGE_EXPORT_DIRECTORY PEInfo::getExportDirectory(LPBYTE pPeBuf, bool bMemAlign = true) {
	// ��ȡ����Ŀ¼
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = GetImageDataDirectory(pPeBuf);
	// ��ȡ�������������RVA
	DWORD RVA = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	// �����ڴ�����־��������������������ļ��е�ƫ����
	DWORD offset = bMemAlign ? RVA : rva2faddr(pPeBuf, RVA);
	// ���ص�����������ָ��
	return (PIMAGE_EXPORT_DIRECTORY)(pPeBuf + offset);

}

DWORD PEInfo::rva2faddr(const char* path, DWORD rva) {
	// ����������
	BYTE buf[PEHBUF_SIZE];
	// ��ȡPE�ļ���������
	int size = readFile(path, buf, PEHBUF_SIZE);
	// ��ȡʧ�ܣ�����0
	if (size == 0) return 0;
	// ����rva2faddr���������ؽ��
	return rva2faddr(buf, rva);
}

DWORD PEInfo::rva2faddr(LPBYTE pPeBuf, DWORD rva) {
	// ���������Ϊ�գ�����0
	if (pPeBuf == NULL) return 0;
	// �������PE�ļ�������0
	if (isPe(pPeBuf) <= 0) return 0;
	// ��ȡ��ѡͷ
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	// ���RVA��ַ��PEͷ���֣�ֱ�ӷ���RVA��ַ
	if (rva <= pOptionalHeader->SectionAlignment) return rva;
	DWORD rvaoff;
	// ��ȡ�ڱ�ͷ
	PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(pPeBuf);
	// ��ȡ�ڱ�ͷ����
	WORD sec_num = GetFileHeader(pPeBuf)->NumberOfSections;
	// ����ÿһ���ڱ�ͷ
	for (int i = 0; i < sec_num; i++) {
		// ����RVA��ַ����ڽڱ�ͷ��ƫ����
		rvaoff = rva - pSecHeader[i].VirtualAddress;
		// ���ƫ�����ڽڱ�ͷ��Ӧ���ڴ��С֮��
		if (rvaoff >= 0 && rvaoff <= pSecHeader[i].Misc.VirtualSize) {
			// ���ض�Ӧ���ļ�ƫ�Ƶ�ַ
			return rvaoff + pSecHeader[i].PointerToRawData;
		}
	}
	// ת��ʧ�ܣ�����0
	return 0;

}

DWORD PEInfo::faddr2rva(const char* path, DWORD faddr) {
	BYTE buf[PEHBUF_SIZE];
	// ��ȡ�ļ���������
	if (readFile(path, buf, PEHBUF_SIZE) <= 0) return 0;
	// ����faddr2rva
	return faddr2rva(buf, faddr);

}
DWORD PEInfo::faddr2rva(LPBYTE pPeBuf, DWORD faddr) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	// ���С�ڵ���FileAlignment������Ҫת��
	if (faddr <= pOptionalHeader->FileAlignment) return faddr;
	DWORD faddroff;
	PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(pPeBuf);
	WORD sec_num = GetFileHeader(pPeBuf)->NumberOfSections;
	for (int i = 0; i < sec_num; i++) {
		// ��������ڵ�ǰ�ε�ƫ��
		faddroff = faddr - pSecHeader[i].PointerToRawData;
		// ����ڵ�ǰ���ڣ���ת��ΪRVA��ַ
		if (faddroff >= 0 && faddroff <= pSecHeader[i].SizeOfRawData) {
			return faddroff + pSecHeader[i].VirtualAddress;
		}
	}
	return 0;
}

DWORD PEInfo::toAlign(DWORD num, DWORD align) {
	// ������
	DWORD r = num % align;
	// ��ԭ����ȥ�������õ���ӽ���������
	num -= r;
	// ���������Ϊ0�������һ��align��ֵ
	if (r != 0) num += align;
	return num;
}


DWORD PEInfo::GetOEPRVA(const char* path) {
	BYTE buf[PEHBUF_SIZE];
	// ��ȡPE�ļ�
	readFile(path, buf, PEHBUF_SIZE);
	// ��ȡOEP RVA
	return GetOEPRVA(buf);
}

DWORD PEInfo::GetOEPRVA(LPBYTE pPeBuf) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	if (pOptionalHeader == NULL) {
		return 0;
	}
	return pOptionalHeader->AddressOfEntryPoint;
}

WORD PEInfo::GetSectionNum(LPBYTE pPeBuf) {
	PIMAGE_FILE_HEADER pFileHeader = GetFileHeader(pPeBuf);
	if (pFileHeader == NULL) {
		return 0;
	}
	// ��ȡPE�ļ��ڵ�����
	return pFileHeader->NumberOfSections;
}

int PEInfo::FindRvaSectIdx(LPBYTE pPeBuf, DWORD rva) {
	if (pPeBuf == NULL || rva == 0) {
		return -1;
	}
	// ��ȡ�ڱ�
	auto pSecHeader = GetSectionHeader(pPeBuf);
	// ��ȡ�ڱ�����
	WORD n = GetSectionNum(pPeBuf);
	for (int i = 0; i < n; i++) {
		// �ж�rva�Ƿ��ڵ�ǰ����
		if (rva >= pSecHeader[i].VirtualAddress && rva < pSecHeader[i].VirtualAddress + pSecHeader[i].Misc.VirtualSize) return i;
	}

	return -1;
}

// ��ȡ PE �ļ����ڴ��е�ӳ���С
// path: �ļ�·��
// return: PE �ļ����ڴ��е�ӳ���С���������򷵻� 0
DWORD PEInfo::GetPeMemSize(const char* path) {
	BYTE buf[PEHBUF_SIZE];
	readFile(path, buf, PEHBUF_SIZE);
	return GetPeMemSize(buf);
}

// ��ȡ PE �ļ����ڴ��е�ӳ���С
// pPeBuf: PE �ļ����ֽ���
// return: PE �ļ����ڴ��е�ӳ���С���������򷵻� 0
DWORD PEInfo::GetPeMemSize(LPBYTE pPeBuf) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	return GetOptionalHeader(pPeBuf)->SizeOfImage;
}

// ��ȡ PE �ļ��еĸ��ǲ��С
// path: �ļ�·��
// return: PE �ļ��еĸ��ǲ��С���������򷵻ش������
DWORD PEInfo::GetOverlaySize(const char* path) {

	BYTE buf[PEHBUF_SIZE];
	DWORD filesize;

	filesize = GetFileSize(path);
	if (filesize == 0) return 0;
	readFile(path, buf, PEHBUF_SIZE);

	int res = isPe(buf);
	if (res > 0) return GetOverlaySize(buf, filesize);
	return res;
}

// ��ȡ PE �ļ��еĸ��ǲ��С
// pFileBuf: PE �ļ����ֽ���
// dwFileSize: �ļ���С
// return: PE �ļ��еĸ��ǲ��С���������򷵻ش������
DWORD PEInfo::GetOverlaySize(LPBYTE pFileBuf, DWORD dwFileSize) {
	PIMAGE_FILE_HEADER pFileHeader = GetFileHeader(pFileBuf);
	PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(pFileBuf);
	WORD sec_num = pFileHeader->NumberOfSections;
	DWORD olaysize = dwFileSize - (pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData);
	return olaysize;
}

DWORD PEInfo::readOverlay(const char* path, LPBYTE pOverlay) {
	if (pOverlay == NULL) return 0;
	DWORD filesize = GetFileSize(path);
	if (filesize == 0) return 0;
	LPBYTE pFileBuf = new BYTE[filesize];
	readFile(path, pFileBuf, filesize);
	int res = isPe(pFileBuf);
	if (res > 0) {
		res = readOverlay(pFileBuf, filesize, pOverlay);
	}
	delete[] pFileBuf;
	return res;
}

DWORD PEInfo::readOverlay(LPBYTE pFileBuf, DWORD dwFileSize, LPBYTE pOverlay) {
	DWORD olaysize = GetOverlaySize(pFileBuf, dwFileSize);
	if (olaysize > 0) memcpy(pOverlay, pFileBuf + dwFileSize - olaysize, olaysize);
	return olaysize;
}

DWORD PEInfo::va2rva(const char* path, DWORD va) {
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return va2rva(buf, va);
}

DWORD PEInfo::va2rva(LPBYTE pPeBuf, DWORD va) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	return (DWORD)(va - GetOptionalHeader(pPeBuf)->ImageBase);
}
DWORD PEInfo::rva2va(const char* path, DWORD rva) {
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return rva2va(buf, rva);
}
DWORD PEInfo::rva2va(LPBYTE pPeBuf, DWORD rva) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	return rva + GetOptionalHeader(pPeBuf)->ImageBase;
}
DWORD PEInfo::faddr2va(const char* path, DWORD faddr) {
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return faddr2va(buf, faddr);
}
DWORD PEInfo::faddr2va(LPBYTE pPeBuf, DWORD faddr) {
	if (pPeBuf == NULL) return 0;
	return rva2va(pPeBuf, faddr2rva(pPeBuf, faddr));
}
DWORD PEInfo::va2faddr(const char* path, DWORD va) {
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return va2faddr(buf, va);
}
DWORD PEInfo::va2faddr(LPBYTE pPeBuf, DWORD va) {
	if (pPeBuf == NULL) return 0;
	return rva2faddr(pPeBuf, va2rva(pPeBuf, va));
}



PEInfo::PEInfo(const char* path, bool isMemAlign) : PEInfo() {
	openPeFile(path, isMemAlign);
}

PEInfo::PEInfo(LPBYTE pPeBuf, DWORD filesize, bool isCopyMem, bool isMemAlign) :PEInfo() {
	attachPeBuf(pPeBuf, filesize, isCopyMem, isMemAlign);
}

void PEInfo::copy(const PEInfo& pe, bool isCopyMem) {
	attachPeBuf(pe.getPeBuf(), pe.getPeBufSize(), isCopyMem, pe.isMemAlign(), pe.getOverlayBuf(), pe.getOverlayBufSize());
	strcpy(this->m_szFilePath, pe.m_szFilePath);
}

PEInfo::PEInfo(const PEInfo& pe) {
	copy(pe, true);
}

PEInfo& PEInfo::operator=(PEInfo& pe) {
	copy(pe, true);
	return *this;
}

DWORD PEInfo::openPeFile(const char* path, bool bMemAlign)
{
	// �ر�֮ǰ�򿪵�PE�ļ�����ʼ��һЩ����
	closePeFile();
	// �����Ƿ����ڴ�ҳ�����ѡ��
	m_bMemAlign = bMemAlign;
	// ���PE�ļ��ѱ�ӳ�䵽�ڴ�
	m_bMemAlloc = true;

	// ��ȡ�ļ���С�����仺����
	DWORD filesize = GetFileSize(path);
	// ��ʼ��ӳ���Ĵ�СΪ0
	DWORD loadsize = 0;
	// �����㹻��Ļ��������ڶ�ȡ�ļ�
	LPBYTE pFileBuf = new BYTE[filesize];

	// ��ȡ�ļ�����
	if (readFile(path, (LPBYTE)pFileBuf, 0) <= 0) return -3;

	// �ж��Ƿ�ΪPE�ļ�
	if (PEInfo::isPe((LPBYTE)pFileBuf) > 0) {
		// �������һ���ڵ�ĩβ��ַ
		DWORD last_faddr;
		// ��ȡPEͷ����Ϣ
		auto pNtHeader = PEInfo::GetNtHeader(pFileBuf);
		// ��ȡ��ͷ����Ϣ
		auto pSecHeader = PEInfo::GetSectionHeader(pFileBuf);
		// ����ӳ���Ĵ�С
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		// ������
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;
		// ����overlay��λ��
		last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		// �������Ҫ�����ڴ�ҳ����
		if (bMemAlign == false) {
			// ֱ��ʹ�ö�ȡ���ļ�������ΪPE�ļ���ӳ������
			m_pPeBuf = pFileBuf;
			// PE�ļ�ӳ���Ĵ�СΪ���һ���ڵ�ĩβ��ַ
			m_dwPeBufSize = last_faddr;
			// ����PE�ļ���ĸ������ݴ�С
			m_dwOverlayBufSize = filesize - last_faddr;
			// ����ļ�ĩβ���ڸ�������
			if (last_faddr < filesize) {
				// ����������ָ��ָ�򸽼������ڻ������е�λ��
				m_pOverlayBuf = pFileBuf + last_faddr;
				// ���¸������ݵĴ�С
				m_dwOverlayBufSize = filesize - last_faddr;
			}
			// ����ӳ���Ĵ�С
			loadsize = filesize;
		}
		// �����Ҫ�����ڴ�ҳ����
		else {
			// PE�ļ�ӳ���Ĵ�СΪPEͷ����ָ����ӳ���С
			loadsize = memsize;
			// ����PE�ļ�ӳ���Ĵ�С
			m_dwPeBufSize = memsize;
			m_pPeBuf = new BYTE[memsize];
			memset(m_pPeBuf, 0, memsize);
			// ����PEͷ���ͽڱ���Ϣ���ڴ���
			memcpy(m_pPeBuf, pFileBuf, pNtHeader->OptionalHeader.SizeOfHeaders);
			for (WORD i = 0; i < sec_num; i++)//��ֵ
			{
				memcpy(m_pPeBuf + pSecHeader[i].VirtualAddress, pFileBuf + pSecHeader[i].PointerToRawData, pSecHeader[i].SizeOfRawData);
			}
			// ����ļ�����overlay�����Ƶ�overlay������
			if (last_faddr < filesize) {
				m_dwOverlayBufSize = filesize - last_faddr;
				m_pOverlayBuf = new BYTE[m_dwOverlayBufSize];
				memcpy(m_pOverlayBuf, pFileBuf + last_faddr, m_dwOverlayBufSize);
				loadsize += m_dwOverlayBufSize;
			}
			delete[] pFileBuf;
		}
	}
	return loadsize;
}

int PEInfo::attachPeBuf(LPBYTE pPeBuf, DWORD dwFileBufSize, bool bCopyMem, bool bMemAlign, LPBYTE pOverlayBuf, DWORD dwOverLayBufSize) {
	// ��� pPeBuf Ϊ NULL����ֱ�ӷ��� 0��
	if (pPeBuf == NULL) return 0;
	m_bMemAlloc = bCopyMem;
	m_bMemAlign = bMemAlign;
	// �ر�֮ǰ���ص� PE �ļ�����ȷ�� PEInfo �����в�����������ļ������ݡ�
	closePeFile();
	// ��� pPeBuf �Ƿ�����Ч�� PE �ļ��������ؼ������
	int res = isPe((LPBYTE)pPeBuf);
	if (res > 0) {
		// ��� bCopyMem Ϊ true����Ϊ�����������µ��ڴ沢���ƻ�����������
		if (bCopyMem) {
			m_pPeBuf = new BYTE[dwFileBufSize];
			memcpy(m_pPeBuf, pPeBuf, dwFileBufSize);
			// ����и���������Ϊ������ڴ沢���丱�����Ƶ����ڴ��С�
			if (dwOverLayBufSize > 0) {
				m_pOverlayBuf = new BYTE[dwOverLayBufSize];
				memcpy(m_pOverlayBuf, pOverlayBuf, dwOverLayBufSize);
			}
		}
		// ��� bCopyMem Ϊ false����ֱ�ӽ� pPeBuf �� pOverlayBuf ��ֵ����Ӧ�ĳ�Ա������
		else {
			m_pPeBuf = pPeBuf;
			m_pOverlayBuf = pOverlayBuf;
		}
		// ����������С�͸��������С����Ϊָ��ֵ��
		m_dwPeBufSize = dwFileBufSize;
		m_dwOverlayBufSize = dwOverLayBufSize;
	}
	return res;
}
void PEInfo::iniValue() {
	m_bMemAlign = true;
	m_bMemAlloc = true;

	memset(m_szFilePath, 0, MAX_PATH);
	m_pPeBuf = 0;
	m_dwPeBufSize = 0;
	m_pOverlayBuf = NULL;
	m_dwOverlayBufSize = 0;
}


void PEInfo::closePeFile() {
	memset(m_szFilePath, 0, MAX_PATH);
	if (m_bMemAlloc == true && m_pPeBuf != NULL) delete[] m_pPeBuf;
	if (m_bMemAlloc == true && m_pOverlayBuf != NULL) delete[] m_pOverlayBuf;
	m_pPeBuf = NULL;
	m_dwPeBufSize = 0;
	m_pOverlayBuf = NULL;
	m_dwOverlayBufSize = 0;
}

int PEInfo::isPe() {
	return PEInfo::isPe(m_pPeBuf);
}


LPBYTE PEInfo::getPeBuf() const {
	return m_pPeBuf;
}

DWORD PEInfo::getPeBufSize() const {
	return m_dwPeBufSize;
}

bool PEInfo::isMemAlign() const {
	return m_bMemAlign;//�����pe�ļ��Ƿ�Ϊ�ڴ����
}

LPBYTE PEInfo::getOverlayBuf() const {
	return m_pOverlayBuf;
}
DWORD PEInfo::getOverlayBufSize() const {
	return m_dwOverlayBufSize;
}

bool PEInfo::isMemAlloc() const {
	return m_bMemAlloc;//�Ƿ��ڴ�Ϊ�˴������
}

const char* const PEInfo::getFilePath() const {
	return m_szFilePath;
}

DWORD PEInfo::getAlignSize() const {
	return m_bMemAlign ?
		const_cast<PEInfo*>(this)->getOptionalHeader()->SectionAlignment :
		const_cast<PEInfo*>(this)->getOptionalHeader()->FileAlignment;
}
DWORD PEInfo::toAlign(DWORD num) const {
	return toAlign(num, getAlignSize());
}

DWORD PEInfo::getPeMemSize() const {
	return GetPeMemSize(m_pPeBuf);
}


PIMAGE_NT_HEADERS PEInfo::getNtHeader(){
	return GetNtHeader(m_pPeBuf);
}
PIMAGE_FILE_HEADER PEInfo::getFileHeader() {
	return GetFileHeader(m_pPeBuf);
}
PIMAGE_OPTIONAL_HEADER PEInfo::getOptionalHeader() {
	return GetOptionalHeader(m_pPeBuf);
}
PIMAGE_DATA_DIRECTORY PEInfo::getImageDataDirectory() {
	return GetImageDataDirectory(m_pPeBuf);
}
PIMAGE_SECTION_HEADER PEInfo::getSectionHeader() {
	return GetSectionHeader(m_pPeBuf);
}
PIMAGE_IMPORT_DESCRIPTOR PEInfo::getImportDescriptor() {
	return getImportDescriptor(m_pPeBuf);
}
PIMAGE_EXPORT_DIRECTORY PEInfo::getExportDirectory() {
	return getExportDirectory(m_pPeBuf);
}
DWORD PEInfo::getOepRva() {
	return GetOEPRVA(m_pPeBuf);
}
WORD PEInfo::getSectionNum() {
	return GetSectionNum(m_pPeBuf);
}
int PEInfo::findRvaSectIdx(DWORD rva) {
	return FindRvaSectIdx(m_pPeBuf, rva);
}

DWORD PEInfo::rva2faddr(DWORD rva) const {
	return rva2faddr(m_pPeBuf, rva);
}
DWORD PEInfo::faddr2rva(DWORD faddr) const {
	return faddr2rva(m_pPeBuf, faddr);
}
DWORD PEInfo::va2rva(DWORD va) const {
	return va2rva(m_pPeBuf, va);
}
DWORD PEInfo::rva2va(DWORD rva) const {
	return rva2va(m_pPeBuf, rva);
}
DWORD PEInfo::faddr2va(DWORD faddr) const {
	return faddr2va(m_pPeBuf, faddr);
}
DWORD PEInfo::va2faddr(DWORD va) const {
	return va2faddr(m_pPeBuf, va);
}