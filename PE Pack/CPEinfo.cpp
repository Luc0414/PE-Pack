#include "CPEinfo.h"

void CPEinfo::initparam() {
	pDosHeader = NULL;
	pNtHeader = NULL;
	pFileHeader = NULL;
	pData = NULL;
	hFile = NULL;
	dwFileSize = 0;
	pOptionHeader = NULL;
	pSectionHeader = NULL;
}

void CPEinfo::init() {
	dwFileSize = ::GetFileSize(hFile, NULL);
	if (INVALID_FILE_SIZE == dwFileSize) {
		printf("GetFileSize() 错误: %d", GetLastError());
		return;
	}

	/* 分配内存来存储文件内容 */
	pData = (char*)malloc(dwFileSize);
	if (NULL == pData) {
		printf("malloc() Error");
		return;
	}

	/* 读取指定文件到内存 */
	DWORD dwRet = 0;
	BOOL isReadFile = ReadFile(hFile, pData, dwFileSize, &dwRet, NULL);
	if (FALSE == isReadFile) {
		printf("ReadFile() Error : %d", GetLastError());
		return;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pData;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pData + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER) & (pNtHeader->FileHeader);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + sizeof(IMAGE_NT_HEADERS));
}
CPEinfo::CPEinfo(LPCWSTR lpFileName)
{
	initparam();
	/* 打开文件 */
	hFile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		printf("CreateFile() 错误 : %d", GetLastError());
		CloseHandle(hFile);
		return;
	}

	init();
}

CPEinfo::CPEinfo(LPCSTR lpFileName)
{

	initparam();
	/* 打开文件 */
	hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		printf("CreateFile() 错误 : %d", GetLastError());
		CloseHandle(hFile);
		return;
	}

	init();
}

CPEinfo::~CPEinfo() {
	CloseHandle(hFile);
}


PIMAGE_DOS_HEADER CPEinfo::GetDosHeader() {
	return pDosHeader;
}

PIMAGE_NT_HEADERS CPEinfo::GetNtHeader() {
	return pNtHeader;
}

PIMAGE_FILE_HEADER CPEinfo::GetFileHeader() {
	return pFileHeader;
}

PIMAGE_OPTIONAL_HEADER CPEinfo::GetOptionHeader() {
	return pOptionHeader;
}

PIMAGE_SECTION_HEADER CPEinfo::GetSectionHeader() {
	return pSectionHeader;
}

PIMAGE_DATA_DIRECTORY CPEinfo::GetDataDirectory() {
	return pOptionHeader->DataDirectory;
}

DWORD CPEinfo::GetSectionNumber() {
	return pFileHeader->NumberOfSections;
}

DWORD CPEinfo::GetSizeOfOptionHeader() {
	return pFileHeader->SizeOfOptionalHeader;
}

DWORD CPEinfo::GetAddressOfEntryPotin() {
	return pOptionHeader->AddressOfEntryPoint;
}

DWORD CPEinfo::GetImageBase() {
	return pOptionHeader->ImageBase;
}

DWORD CPEinfo::GetSectionAlignment() {
	return pOptionHeader->SectionAlignment;
}

DWORD CPEinfo::GetFileAlignment() {
	return pOptionHeader->FileAlignment;
}

DWORD CPEinfo::GetSizeImage() {
	return pOptionHeader->SizeOfImage;
}

DWORD CPEinfo::GetSizeOfHeaders() {
	return pOptionHeader->SizeOfHeaders;
}

DWORD CPEinfo::GetNumberOfRvaAndSizes() {
	return pOptionHeader->NumberOfRvaAndSizes;
}

PIMAGE_SECTION_HEADER CPEinfo::GetSectionHeader(DWORD id) {
	if (id > pFileHeader->NumberOfSections) {
		printf("输入ID超过节数量\n");
		return NULL;
	}
	return (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + sizeof(IMAGE_SECTION_HEADER) * id);
}

PSECTION_CHARACTERISTICS CPEinfo::GetSectionCharacteristics(ULONG * Characteristics) {
	return (PSECTION_CHARACTERISTICS)Characteristics;
}

PIMAGE_IMPORT_DESCRIPTOR CPEinfo::GetImportDescriptor(DWORD id) {
	/* 获取导入表在文件的偏移位置 */
	DWORD ImportFOA = RVA2Offset(pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	/* 移动到第ID个导入表 */
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pData + ImportFOA + sizeof(IMAGE_IMPORT_DESCRIPTOR) * id);
	if (pImportDescriptor->OriginalFirstThunk == 0 && pImportDescriptor->TimeDateStamp == 0 && pImportDescriptor->ForwarderChain == 0 && pImportDescriptor->Name == 0 && pImportDescriptor->FirstThunk == 0) {
		return NULL;
	}
	return pImportDescriptor;
}

DWORD CPEinfo::RVA2Offset(DWORD dwExpotRVA) {
	PIMAGE_SECTION_HEADER pSection = GetSectionHeader();
	for (int i = 0; i < GetSectionNumber(); i++) {
		if (dwExpotRVA >= pSection[i].VirtualAddress && dwExpotRVA < (pSection[i].VirtualAddress + pSection[i].SizeOfRawData)) {
			return pSection[i].PointerToRawData + (dwExpotRVA - pSection[i].VirtualAddress);
		}
	}
	return 0;
}


DWORD CPEinfo::RVA2Name(DWORD dwExpotRVA) {
	PIMAGE_SECTION_HEADER pSection = GetSectionHeader();
	for (int i = 0; i < GetSectionNumber(); i++) {
		if (dwExpotRVA >= pSection[i].VirtualAddress && dwExpotRVA < (pSection[i].VirtualAddress + pSection[i].SizeOfRawData)) {
			return (DWORD)pSection[i].Name;
		}
	}
	return 0;
}

DWORD CPEinfo::CalcFileAlignment(DWORD Size) {
	return (Size / 0x200) > 0 ? ((Size / 0x200) + 1) * 0x200 : Size;
}

DWORD CPEinfo::CalcSectionAlignment(DWORD Size) {
	return (Size / 0x1000) > 0 ? ((Size / 0x1000) + 1) * 0x1000 : Size;
}
