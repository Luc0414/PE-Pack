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
	/* ��ȡ DOSͷ */
	PIMAGE_DOS_HEADER GetDosHeader();
	/* ��ȡ NTͷ */
	PIMAGE_NT_HEADERS GetNtHeader();
	/* ��ȡ NT->�ļ�ͷ */
	PIMAGE_FILE_HEADER GetFileHeader();
	/* ��ȡ NT->��ѡͷ */
	PIMAGE_OPTIONAL_HEADER GetOptionHeader();
	/* ��ȡ �ڱ�ͷ */
	PIMAGE_SECTION_HEADER GetSectionHeader();
	/* ��ȡ NT->��ѡͷ->����Ŀ¼ */
	PIMAGE_DATA_DIRECTORY GetDataDirectory();
	/* ��ȡ����Ϣ */
	PIMAGE_SECTION_HEADER GetSectionHeader(DWORD id);
	/* ���ؽ����� */
	PSECTION_CHARACTERISTICS GetSectionCharacteristics(ULONG * Characteristics);
	/* ��ȡ����� */
	PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(DWORD id);

public:
	/* ��ȡ������ */
	DWORD GetSectionNumber();
	/* ��ȡ��ѡ��Ĵ�С */
	DWORD GetSizeOfOptionHeader();
	/* ��ȡ�������RVA */
	DWORD GetAddressOfEntryPotin();
	/* ��ȡ�����ַ */
	DWORD GetImageBase();
	/* ��ȡ�ڴ�����С */
	DWORD GetSectionAlignment();
	/* ��ȡ�ļ������С */
	DWORD GetFileAlignment();
	/* ��ȡ�������ڴ��ռ�ÿռ� */
	DWORD GetSizeImage();
	/* ��ȡPEͷ��С��������FileAlignment�������� */
	DWORD GetSizeOfHeaders();
	/* DataDirectory�ĸ���*/
	DWORD GetNumberOfRvaAndSizes();
	/* RVA to FOA */
	DWORD RVA2Offset(DWORD dwExpotRVA);
	/* RVA ���ڽ��� */
	DWORD RVA2Name(DWORD dwExpotRVA);
	/* ����DWORD�������ļ����� */
	DWORD CalcFileAlignment(DWORD Size);
	/* ����DWORD�������ڴ���� */
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