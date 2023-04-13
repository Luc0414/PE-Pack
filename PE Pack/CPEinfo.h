#pragma once
#include <iostream>
#include <Windows.h>
#include <stdio.h>

typedef struct
{
	ULONG SCN_TYPE_DSECT : 1;
	ULONG SCN_TYPE_NOLOAD : 1;
	ULONG SCN_TYPE_GROUP : 1;
	ULONG SCN_TYPE_NO_PAD : 1;
	ULONG SCN_TYPE_COPY : 1;
	ULONG SCN_CNT_CODE : 1;
	ULONG SCN_CNT_INITIALIZED_DATA : 1;
	ULONG SCN_CNT_UNINITIALIZED_DATA : 1;
	ULONG SCN_LNK_OTHER : 1;
	ULONG SCN_LNK_INFO : 1;
	ULONG SCN_TYPE_OVER : 1;
	ULONG SCN_LNK_REMOVE : 1;
	ULONG SCN_LNK_COMDAT : 1;
	ULONG : 1;
	ULONG SCN_NO_DEFER_SPEC_EXC : 1;
	ULONG SCN_GPREL : 1;
	ULONG SCN_MEM_SYSHEAP : 1;
	ULONG SCN_MEM_16BIT : 1;
	ULONG SCN_MEM_LOCKED : 1;
	ULONG SCN_MEM_PRELOAD : 1;
	ULONG SCN_ALIGN_1BYTES : 1;
	ULONG SCN_ALIGN_2BYTES : 1;
	ULONG SCN_ALIGN_8BYTES : 1;
	ULONG SCN_ALIGN_128BYTES : 1;
	ULONG SCN_LNK_NRELOC_OVFL : 1;
	ULONG SCN_MEM_DISCARDABLE : 1;
	ULONG SCN_MEM_NOT_CACHED : 1;
	ULONG SCN_MEM_NOT_PAGED : 1;
	ULONG SCN_MEM_SHARED : 1;
	ULONG SCN_MEM_EXECUTE : 1;
	ULONG SCN_MEM_READ : 1;
	ULONG SCN_MEM_WRITE : 1;
} SECTION_CHARACTERISTICS,*PSECTION_CHARACTERISTICS;


class CPEinfo
{
public:
	CPEinfo(LPCWSTR lpFileName);
	CPEinfo(LPCSTR lpFileName);
	~CPEinfo();

public:
	/* 获取 DOS头 */
	PIMAGE_DOS_HEADER GetDosHeader();
	/* 获取 NT头 */
	PIMAGE_NT_HEADERS GetNtHeader();
	/* 获取 NT->文件头 */
	PIMAGE_FILE_HEADER GetFileHeader();
	/* 获取 NT->可选头 */
	PIMAGE_OPTIONAL_HEADER GetOptionHeader();
	/* 获取 节表头 */
	PIMAGE_SECTION_HEADER GetSectionHeader();
	/* 获取 NT->可选头->数据目录 */
	PIMAGE_DATA_DIRECTORY GetDataDirectory();
	/* 获取节信息 */
	PIMAGE_SECTION_HEADER GetSectionHeader(DWORD id);
	/* 返回节属性 */
	PSECTION_CHARACTERISTICS GetSectionCharacteristics(ULONG * Characteristics);
	/* 获取导入表 */
	PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(DWORD id);

public:
	/* 获取节数量 */
	DWORD GetSectionNumber();
	/* 获取可选项的大小 */
	DWORD GetSizeOfOptionHeader();
	/* 获取程序入口RVA */
	DWORD GetAddressOfEntryPotin();
	/* 获取程序基址 */
	DWORD GetImageBase();
	/* 获取内存对齐大小 */
	DWORD GetSectionAlignment();
	/* 获取文件对齐大小 */
	DWORD GetFileAlignment();
	/* 获取程序在内存的占用空间 */
	DWORD GetSizeImage();
	/* 获取PE头大小，必须是FileAlignment的整数倍 */
	DWORD GetSizeOfHeaders();
	/* DataDirectory的个数*/
	DWORD GetNumberOfRvaAndSizes();
	/* RVA to FOA */
	DWORD RVA2Offset(DWORD dwExpotRVA);
	/* RVA 所在节名 */
	DWORD RVA2Name(DWORD dwExpotRVA);
	/* 传入DWORD，计算文件对齐 */
	DWORD CalcFileAlignment(DWORD Size);
	/* 传入DWORD，计算内存对齐 */
	DWORD CalcSectionAlignment(DWORD Size);

private:
	void initparam();
	void init();

public:
	char* pData;
private:
	HANDLE hFile;
	DWORD dwFileSize;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
};