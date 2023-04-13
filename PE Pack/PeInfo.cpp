#include "PeInfo.h"
#include <fstream>

using namespace std;

// RAII技术，自动管理资源（文件句柄）的释放
class ScopedFile {
public:
	ScopedFile(const char* path, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::binary) : stream_(path, mode)
	{}

	// 析构函数中自动关闭文件句柄
	~ScopedFile() {
		if (stream_.is_open()) {
			stream_.close();
		}
	}

	// & 是 C++ 中的引用运算符。 它创建对它之后的对象的引用。
	std::ifstream& get() { return stream_; }

public:
	std::ifstream stream_;
};

// 获取文件大小
DWORD PEInfo::GetFileSize(const char* path) {
	ScopedFile fin(path);
	// 文件打开失败
	if (!fin.get().good()) return 0;
	// 移动到文件结尾
	fin.get().seekg(0, std::ios::end);
	// 返回当前文件指针的位置，即文件大小
	return static_cast<DWORD>(fin.get().tellg());
}

// 读取文件内容
DWORD PEInfo::readFile(const char* path, LPBYTE pFileBuf, DWORD size) {
	ScopedFile fin(path);
	// 文件打开失败或者传入的指针为空指针
	if (!fin.get().good() || !pFileBuf) return 0;
	// 移动到文件结尾
	fin.get().seekg(0, std::ios::end);
	// 获取文件大小 static_cast C++转换运算符
	const DWORD fsize = static_cast<DWORD>(fin.get().tellg());
	// 移动到文件开头
	fin.get().seekg(0, std::ios::beg);
	if (size == 0 || fsize < size) size = fsize;
	// 读取文件内容到指定缓冲区 reinterpret_cast C++转换运算符 将一种类型的指针转换为另一种类型的指针
	fin.get().read(reinterpret_cast<char*>(pFileBuf), size);
	// 返回实际读取的字节数
	return size;
}

// 从指定路径读取PE文件并加载到指定内存地址中，可以选择是否按照内存对齐规则来加载
DWORD PEInfo::loadPeFile(const char* path, LPBYTE pPeBuf, DWORD* FileBufSize, bool bMemAlign, LPBYTE pOverlayBuf, DWORD* OverlayBufSize) {
	// 如果加载到的内存地址为空，直接返回0
	if (pPeBuf == NULL) return 0;
	DWORD loadsize = 0;
	DWORD filesize = GetFileSize(path);
	// 创建文件缓冲区
	LPBYTE buf = new BYTE[filesize];
	// 读取PE文件到缓冲区中
	if (readFile(path, buf, 0) <= 0) return 0;
	// 判断PE文件是否有效
	if (isPe(buf) > 0) {
		// 获取PE头和节表头
		PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(buf);
		PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(buf);
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;
		DWORD last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		// 如果不按照内存对齐规则来加载
		if (bMemAlign == false) {
			// 直接将PE文件内容复制到目标内存地址中
			memcpy(pPeBuf, buf, filesize);
			// 如果文件缓冲区大小不为空，设置其值为文件大小
			if (FileBufSize != NULL) *FileBufSize = filesize;
			// 如果存在overlay数据，将其读取到指定缓冲区中
			if (last_faddr < filesize) {
				memcpy(pOverlayBuf, buf + last_faddr, filesize - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
			}
			loadsize = filesize;
		}
		else {
			// 按照内存对齐规则来加载
			// 先将目标内存地址清零
			memset(pPeBuf, 0, memsize);
			loadsize = memsize;
			// 复制PE文件头到目标内存地址中
			memcpy(pPeBuf, buf, pNtHeader->OptionalHeader.SizeOfHeaders);
			// 复制每个节的内容到目标内存地址中
			for (int i = 0; i < sec_num; i++) {
				memcpy(pPeBuf + pSecHeader[i].VirtualAddress, buf + pSecHeader[i].PointerToRawData, pSecHeader[i].SizeOfRawData);
			}
			// 如果存在overlay数据，将其读取到指定缓冲区中
			if (last_faddr < filesize) {
				memcpy(pOverlayBuf, buf + last_faddr, filesize - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
				loadsize += filesize - last_faddr;
			}
		}
		// 释放内存
		delete[] buf;
	}

	return loadsize;

}
// 判断给定的文件是否为PE格式
int PEInfo::isPe(const char* path) {
	BYTE buf[PEHBUF_SIZE];
	// 读取文件失败，返回-3
	if (readFile(path, (LPBYTE)buf, PEHBUF_SIZE) == 0) return -3;
	// 调用isPe(LPBYTE pPeBuf)函数判断文件是否为PE格式
	return isPe((LPBYTE)buf);
}

// 判断给定的二进制缓冲区是否为PE格式
int PEInfo::isPe(LPBYTE pPeBuf) {
	// 获取PE文件的DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPeBuf;
	// 判断是否为MZ头
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return -1;
	// 获取PE文件的NT头
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pPeBuf);
	// 判断是否为PE头
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return -2;
	// 返回PE头的魔数
	return pNtHeader->OptionalHeader.Magic;
}

// 获取给定二进制缓冲区的NT头指针
PIMAGE_NT_HEADERS PEInfo::GetNtHeader(LPBYTE pPeBuf) {
	// 获取PE文件的DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPeBuf;
	// 获取PE文件的NT头指针
	return (PIMAGE_NT_HEADERS)(pPeBuf + pDosHeader->e_lfanew);
}



// 获取给定二进制缓冲区的节区头指针
PIMAGE_SECTION_HEADER PEInfo::GetSectionHeader(LPBYTE pPeBuf) {
	// 获取PE文件的NT头
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pPeBuf);
	// 获取PE文件的节区头指针
	return (PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader + sizeof(IMAGE_NT_HEADERS));
}

// 获取给定二进制缓冲区的文件头
PIMAGE_FILE_HEADER PEInfo::GetFileHeader(LPBYTE pPeBuf) {
	return &GetNtHeader(pPeBuf)->FileHeader;
}

// 获取给定二进制缓冲区的可选头
PIMAGE_OPTIONAL_HEADER PEInfo::GetOptionalHeader(LPBYTE pPeBuf) {
	return &GetNtHeader(pPeBuf)->OptionalHeader;
}

// 获取给定二进制缓冲区的数据目录
PIMAGE_DATA_DIRECTORY PEInfo::GetImageDataDirectory(LPBYTE pPeBuf) {
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	return pOptionalHeader->DataDirectory;
}


PIMAGE_IMPORT_DESCRIPTOR PEInfo::getImportDescriptor(LPBYTE pPeBuf, bool bMemAlign = true) {
	// 获取数据目录
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = GetImageDataDirectory(pPeBuf);
	// 获取导入描述符表的RVA
	DWORD RVA = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	// 根据内存对齐标志计算出导入描述符表在文件中的偏移量
	DWORD offset = bMemAlign ? RVA : rva2faddr(pPeBuf, RVA);
	// 返回导入描述符表指针
	return (PIMAGE_IMPORT_DESCRIPTOR)(pPeBuf + offset);
}
PIMAGE_EXPORT_DIRECTORY PEInfo::getExportDirectory(LPBYTE pPeBuf, bool bMemAlign = true) {
	// 获取数据目录
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = GetImageDataDirectory(pPeBuf);
	// 获取导出描述符表的RVA
	DWORD RVA = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	// 根据内存对齐标志计算出导出描述符表在文件中的偏移量
	DWORD offset = bMemAlign ? RVA : rva2faddr(pPeBuf, RVA);
	// 返回导出描述符表指针
	return (PIMAGE_EXPORT_DIRECTORY)(pPeBuf + offset);

}

DWORD PEInfo::rva2faddr(const char* path, DWORD rva) {
	// 创建缓冲区
	BYTE buf[PEHBUF_SIZE];
	// 读取PE文件到缓冲区
	int size = readFile(path, buf, PEHBUF_SIZE);
	// 读取失败，返回0
	if (size == 0) return 0;
	// 调用rva2faddr函数，返回结果
	return rva2faddr(buf, rva);
}

DWORD PEInfo::rva2faddr(LPBYTE pPeBuf, DWORD rva) {
	// 如果缓冲区为空，返回0
	if (pPeBuf == NULL) return 0;
	// 如果不是PE文件，返回0
	if (isPe(pPeBuf) <= 0) return 0;
	// 获取可选头
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	// 如果RVA地址在PE头部分，直接返回RVA地址
	if (rva <= pOptionalHeader->SectionAlignment) return rva;
	DWORD rvaoff;
	// 获取节表头
	PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(pPeBuf);
	// 获取节表头数量
	WORD sec_num = GetFileHeader(pPeBuf)->NumberOfSections;
	// 遍历每一个节表头
	for (int i = 0; i < sec_num; i++) {
		// 计算RVA地址相对于节表头的偏移量
		rvaoff = rva - pSecHeader[i].VirtualAddress;
		// 如果偏移量在节表头对应的内存大小之内
		if (rvaoff >= 0 && rvaoff <= pSecHeader[i].Misc.VirtualSize) {
			// 返回对应的文件偏移地址
			return rvaoff + pSecHeader[i].PointerToRawData;
		}
	}
	// 转化失败，返回0
	return 0;

}

DWORD PEInfo::faddr2rva(const char* path, DWORD faddr) {
	BYTE buf[PEHBUF_SIZE];
	// 读取文件到缓冲区
	if (readFile(path, buf, PEHBUF_SIZE) <= 0) return 0;
	// 调用faddr2rva
	return faddr2rva(buf, faddr);

}
DWORD PEInfo::faddr2rva(LPBYTE pPeBuf, DWORD faddr) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	// 如果小于等于FileAlignment，则不需要转化
	if (faddr <= pOptionalHeader->FileAlignment) return faddr;
	DWORD faddroff;
	PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(pPeBuf);
	WORD sec_num = GetFileHeader(pPeBuf)->NumberOfSections;
	for (int i = 0; i < sec_num; i++) {
		// 计算相对于当前段的偏移
		faddroff = faddr - pSecHeader[i].PointerToRawData;
		// 如果在当前段内，则转化为RVA地址
		if (faddroff >= 0 && faddroff <= pSecHeader[i].SizeOfRawData) {
			return faddroff + pSecHeader[i].VirtualAddress;
		}
	}
	return 0;
}

DWORD PEInfo::toAlign(DWORD num, DWORD align) {
	// 求余数
	DWORD r = num % align;
	// 将原数减去余数，得到最接近的整数倍
	num -= r;
	// 如果余数不为0，则加上一个align的值
	if (r != 0) num += align;
	return num;
}


DWORD PEInfo::GetOEPRVA(const char* path) {
	BYTE buf[PEHBUF_SIZE];
	// 读取PE文件
	readFile(path, buf, PEHBUF_SIZE);
	// 获取OEP RVA
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
	// 获取PE文件节的数量
	return pFileHeader->NumberOfSections;
}

int PEInfo::FindRvaSectIdx(LPBYTE pPeBuf, DWORD rva) {
	if (pPeBuf == NULL || rva == 0) {
		return -1;
	}
	// 获取节表
	auto pSecHeader = GetSectionHeader(pPeBuf);
	// 获取节表数量
	WORD n = GetSectionNum(pPeBuf);
	for (int i = 0; i < n; i++) {
		// 判断rva是否在当前节中
		if (rva >= pSecHeader[i].VirtualAddress && rva < pSecHeader[i].VirtualAddress + pSecHeader[i].Misc.VirtualSize) return i;
	}

	return -1;
}

// 获取 PE 文件在内存中的映射大小
// path: 文件路径
// return: PE 文件在内存中的映射大小，若出错则返回 0
DWORD PEInfo::GetPeMemSize(const char* path) {
	BYTE buf[PEHBUF_SIZE];
	readFile(path, buf, PEHBUF_SIZE);
	return GetPeMemSize(buf);
}

// 获取 PE 文件在内存中的映射大小
// pPeBuf: PE 文件的字节流
// return: PE 文件在内存中的映射大小，若出错则返回 0
DWORD PEInfo::GetPeMemSize(LPBYTE pPeBuf) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	return GetOptionalHeader(pPeBuf)->SizeOfImage;
}

// 获取 PE 文件中的覆盖层大小
// path: 文件路径
// return: PE 文件中的覆盖层大小，若出错则返回错误代码
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

// 获取 PE 文件中的覆盖层大小
// pFileBuf: PE 文件的字节流
// dwFileSize: 文件大小
// return: PE 文件中的覆盖层大小，若出错则返回错误代码
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
	// 关闭之前打开的PE文件并初始化一些变量
	closePeFile();
	// 保存是否按照内存页对齐的选项
	m_bMemAlign = bMemAlign;
	// 标记PE文件已被映射到内存
	m_bMemAlloc = true;

	// 获取文件大小并分配缓冲区
	DWORD filesize = GetFileSize(path);
	// 初始化映射后的大小为0
	DWORD loadsize = 0;
	// 申请足够大的缓冲区用于读取文件
	LPBYTE pFileBuf = new BYTE[filesize];

	// 读取文件内容
	if (readFile(path, (LPBYTE)pFileBuf, 0) <= 0) return -3;

	// 判断是否为PE文件
	if (PEInfo::isPe((LPBYTE)pFileBuf) > 0) {
		// 保存最后一个节的末尾地址
		DWORD last_faddr;
		// 获取PE头部信息
		auto pNtHeader = PEInfo::GetNtHeader(pFileBuf);
		// 获取节头部信息
		auto pSecHeader = PEInfo::GetSectionHeader(pFileBuf);
		// 计算映射后的大小
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		// 节数量
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;
		// 计算overlay的位置
		last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		// 如果不需要按照内存页对齐
		if (bMemAlign == false) {
			// 直接使用读取的文件内容作为PE文件的映射内容
			m_pPeBuf = pFileBuf;
			// PE文件映射后的大小为最后一个节的末尾地址
			m_dwPeBufSize = last_faddr;
			// 计算PE文件后的附加数据大小
			m_dwOverlayBufSize = filesize - last_faddr;
			// 如果文件末尾存在附加数据
			if (last_faddr < filesize) {
				// 将附加数据指针指向附加数据在缓冲区中的位置
				m_pOverlayBuf = pFileBuf + last_faddr;
				// 更新附加数据的大小
				m_dwOverlayBufSize = filesize - last_faddr;
			}
			// 更新映射后的大小
			loadsize = filesize;
		}
		// 如果需要按照内存页对齐
		else {
			// PE文件映射后的大小为PE头部中指定的映射大小
			loadsize = memsize;
			// 保存PE文件映射后的大小
			m_dwPeBufSize = memsize;
			m_pPeBuf = new BYTE[memsize];
			memset(m_pPeBuf, 0, memsize);
			// 复制PE头部和节表信息到内存中
			memcpy(m_pPeBuf, pFileBuf, pNtHeader->OptionalHeader.SizeOfHeaders);
			for (WORD i = 0; i < sec_num; i++)//赋值
			{
				memcpy(m_pPeBuf + pSecHeader[i].VirtualAddress, pFileBuf + pSecHeader[i].PointerToRawData, pSecHeader[i].SizeOfRawData);
			}
			// 如果文件中有overlay，复制到overlay缓冲区
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
	// 如果 pPeBuf 为 NULL，则直接返回 0。
	if (pPeBuf == NULL) return 0;
	m_bMemAlloc = bCopyMem;
	m_bMemAlign = bMemAlign;
	// 关闭之前加载的 PE 文件，以确保 PEInfo 对象中不会存在其他文件的数据。
	closePeFile();
	// 检查 pPeBuf 是否是有效的 PE 文件，并返回检查结果。
	int res = isPe((LPBYTE)pPeBuf);
	if (res > 0) {
		// 如果 bCopyMem 为 true，则为缓冲区分配新的内存并复制缓冲区副本。
		if (bCopyMem) {
			m_pPeBuf = new BYTE[dwFileBufSize];
			memcpy(m_pPeBuf, pPeBuf, dwFileBufSize);
			// 如果有覆盖区域，则为其分配内存并将其副本复制到该内存中。
			if (dwOverLayBufSize > 0) {
				m_pOverlayBuf = new BYTE[dwOverLayBufSize];
				memcpy(m_pOverlayBuf, pOverlayBuf, dwOverLayBufSize);
			}
		}
		// 如果 bCopyMem 为 false，则直接将 pPeBuf 和 pOverlayBuf 赋值给相应的成员变量。
		else {
			m_pPeBuf = pPeBuf;
			m_pOverlayBuf = pOverlayBuf;
		}
		// 将缓冲区大小和覆盖区域大小设置为指定值。
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
	return m_bMemAlign;//载入的pe文件是否为内存对齐
}

LPBYTE PEInfo::getOverlayBuf() const {
	return m_pOverlayBuf;
}
DWORD PEInfo::getOverlayBufSize() const {
	return m_dwOverlayBufSize;
}

bool PEInfo::isMemAlloc() const {
	return m_bMemAlloc;//是否内存为此处分配的
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