#pragma once
#include <Windows.h>


#define PEHBUF_SIZE 0X500

typedef struct {
	WORD Offset : 12;  //偏移值
	WORD type : 4;  //重定位属性(方式)
} RELOCOFFSET,* PRELOCOFFSET;

class PEInfo {
public:

	//文件处理

	/**
	 * @brief 获取指定文件的大小。
	 * @param path 文件路径。
	 * @return 文件的大小（单位：字节）。
	 */
	static DWORD GetFileSize(const char* path);

	/**
	 * @brief 读取指定大小的数据块到内存中。
	 * @param path 文件路径。
	 * @param pFileBuf 指向存储读取数据的缓冲区的指针。
	 * @param size 要读取的数据大小（单位：字节）。
	 * @return 实际读取的数据大小（单位：字节）。
	 */
	static DWORD readFile(const char* path, LPBYTE pFileBuf, DWORD size);

	/**
	 * @brief 将一个PE文件从磁盘加载到内存中，可以选择将内存布局与文件布局对齐。
	 * @param path PE文件的路径。
	 * @param pPeBuf 指向存储加载的PE文件的缓冲区的指针。
	 * @param FileBufSize (可选) 一个指向DWORD的指针，它将被设置为加载的PE文件的大小。
	 * @param bMemAlign 如果为真，PE文件将按内存布局对齐，否则将按文件布局对齐。
	 * @param pOverlayBuf (optional) 一个指向缓冲区的指针，PE文件以外的数据将被存储在那里（如果有的话）。
	 * @param OverlayBufSize (optional) 一个指向DWORD的指针，该指针将被设置为PE文件外的数据的大小（如果有的话）。
	 * @return 加载的PE文件的大小，如果加载失败则为0。
	 */
	static DWORD loadPeFile(const char* path, LPBYTE pPeBuf, DWORD* FileBufSize, bool bMemAlign, LPBYTE pOverlayBuf, DWORD* OverlayBufSize);

	/**
	 * @brief 判断一个内存缓冲区是否为PE格式。
	 * @param pPeBuf 指向PE文件缓冲区的指针。
	 * @return 如果缓冲区是PE文件格式，则返回1，否则返回0。
	 */
	static int isPe(LPBYTE pPeBuf);

	/**
	 * @brief 判断一个文件是否为PE格式。
	 * @param path 文件路径。
	 * @return 如果文件是PE文件格式，则返回1，否则返回0。
	 */
	static int isPe(const char* path);

	/**
	 * @brief 将给定数按照指定的对齐方式对齐
	 * @param num 待对齐的数
	 * @param align 对齐方式
	 * @return 对齐后的数
	*/
	static DWORD toAlign(DWORD num, DWORD align);


	// static pe 参数获取
	/**
	 * @brief 获取PE文件的NT头。
	 * @param pPeBuf 指向PE文件缓冲区的指针。
	 * @return 指向PE文件NT头的指针。
	 */
	static PIMAGE_NT_HEADERS GetNtHeader(LPBYTE pPeBuf);

	/**
	 * @brief 获取PE文件的文件头。
	 * @param pPeBuf 指向PE文件缓冲区的指针。
	 * @return 指向PE文件文件头的指针。
	 */
	static PIMAGE_FILE_HEADER GetFileHeader(LPBYTE pPeBuf);

	/**
	 * @brief 获取PE文件的可选头。
	 * @param pPeBuf 指向PE文件缓冲区的指针。
	 * @return 指向PE文件可选头的指针。
	 */
	static PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPBYTE pPeBuf);

	/**
	 * @brief 获取PE文件的数据目录。
	 * @param pPeBuf 指向PE文件缓冲区的指针。
	 * @return 指向PE文件数据目录的指针。
	 */
	static PIMAGE_DATA_DIRECTORY GetImageDataDirectory(LPBYTE pPeBuf);

	/**
	 * @brief 获取PE文件的节表。
	 * @param pPeBuf 指向PE文件缓冲区的指针。
	 * @return 指向PE文件节表的指针。
	 */
	static PIMAGE_SECTION_HEADER GetSectionHeader(LPBYTE pPeBuf);

	/**
	 * @brief 获取PE文件中的导入描述符表。
	 * @param pPeBuf 指向PE文件的指针。
	 * @param bMemAlign 如果为true，则将偏移量按内存对齐，否则按文件对齐。
	 * @return 指向导入描述符表的指针。
	 */
	static PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(LPBYTE pPeBuf, bool bFromFile);

	/**
	 * @brief 获取PE文件中的导出描述符表。
	 * @param pPeBuf 指向PE文件的指针。
	 * @param bMemAlign 如果为true，则将偏移量按内存对齐，否则按文件对齐。
	 * @return 指向导出描述符表的指针。
	 */
	static PIMAGE_EXPORT_DIRECTORY getExportDirectory(LPBYTE pPeBuf, bool bFromFile);

	/**
	 * @brief 获取PE文件入口点RVA
	 * @param path PE文件路径
	 * @return PE文件入口点RVA
	 */
	static DWORD GetOEPRVA(const char* path);

	/**
	 * @brief 获取PE文件入口点RVA
	 * @param pPeBuf PE文件内存缓冲区指针
	 * @return PE文件入口点RVA
	 */
	static DWORD GetOEPRVA(LPBYTE pPeBuf);

	/**
	 * @brief 获取PE文件节表数量
	 * @param pPeBuf PE文件内存缓冲区指针
	 * @return PE文件节表数量
	 */
	static WORD GetSectionNum(LPBYTE pPeBuf);

	/**
	 * @brief 查找指定RVA所在的节表序号
	 * @param pPeBuf PE文件内存缓冲区指针
	 * @param rva 要查找的RVA
	 * @return 如果找到则返回节表序号，否则返回-1
	 */
	static int FindRvaSectIdx(LPBYTE pPeBuf, DWORD rva);

	/**
	 * @brief 获取PE文件在内存中载入所需大小
	 * @param path PE文件路径
	 * @return DWORD PE文件在内存中载入所需大小，以字节为单位
	 */
	static DWORD GetPeMemSize(const char* path);

	/**
	 * @brief 获取PE文件在内存中载入所需大小
	 * @param pPeBuf 指向PE文件数据缓冲区的指针
	 * @return DWORD PE文件在内存中载入所需大小，以字节为单位
	*/
	static DWORD GetPeMemSize(LPBYTE pPeBuf);

	/**
	 * @brief 获取PE文件的附加数据大小
	 * @param path PE文件路径
	 * @return DWORD PE文件的附加数据大小，以字节为单位，若无附加数据则返回0
	 */
	static DWORD GetOverlaySize(const char* path);

	/**
	 * @brief 获取PE文件的附加数据大小
	 * @param pFileBuf 指向PE文件数据缓冲区的指针
	 * @param dwFileSize PE文件数据缓冲区大小，以字节为单位
	 * @return DWORD PE文件的附加数据大小，以字节为单位，若无附加数据则返回0
	 */
	static DWORD GetOverlaySize(LPBYTE pFileBuf, DWORD dwFileSize);

	/**
	 * @brief 读取PE文件的附加数据
	 * @param path PE文件路径
	 * @param pOverlay 指向存储PE文件附加数据的缓冲区的指针
	 * @return DWORD 读取的PE文件附加数据大小，以字节为单位，若无附加数据则返回0
	 */
	static DWORD readOverlay(const char* path, LPBYTE pOverlay);

	/**
	 * @brief 读取PE文件的附加数据
	 * @param pFileBuf 指向PE文件数据缓冲区的指针
	 * @param dwFileSize PE文件数据缓冲区大小，以字节为单位
	 * @param pOverlay 指向存储PE文件附加数据的缓冲区的指针
	 * @return DWORD 读取的PE文件附加数据大小，以字节为单位，若无附加数据则返回0
	*/
	static DWORD readOverlay(LPBYTE pFileBuf, DWORD dwFileSize, LPBYTE pOverlay);

	// 地址转换函数
	/**
	 * @brief 从PE文件中RVA地址转化为文件偏移地址
	 * @param path PE文件的路径
	 * @param rva 待转化的RVA地址
	 * @return 转化后的文件偏移地址，如果转化失败则为0
	 */
	static DWORD rva2faddr(const char* path, DWORD rva);

	/**
	 * @brief 从PE文件中RVA地址转化为文件偏移地址。
	 * @param pPeBuf 指向已加载PE文件的缓冲区的指针。
	 * @param rva 待转化的RVA地址。
	 * @return 转化后的文件偏移地址，如果转化失败则为0。
	 */
	static DWORD rva2faddr(LPBYTE pPeBuf, DWORD rva);

	/**
	 * @brief 从文件偏移地址转化为PE文件中的RVA地址。
	 * @param path PE文件的路径。
	 * @param faddr 待转化的文件偏移地址。
	 * @return 转化后的RVA地址，如果转化失败则为0。
	 */
	static DWORD faddr2rva(const char* path, DWORD faddr);

	/**
	 * @brief 从PE文件中的文件偏移地址转化为RVA地址。
	 * @param pPeBuf 指向已加载PE文件的缓冲区的指针。
	 * @param faddr 待转化的文件偏移地址。
	 * @return 转化后的RVA地址，如果转化失败则为0。
	 */
	static DWORD faddr2rva(LPBYTE pPeBuf, DWORD faddr);

	/**
	 * @brief 将指定路径的PE文件中的VA地址转化为RVA地址。
	 * @param path PE文件的路径。
	 * @param va 待转化的VA地址。
	 * @return 转化后的RVA地址，如果转化失败则为0。
	 */
	static DWORD va2rva(const char* path, DWORD va);

	/**
	 * @brief 将指定PE文件的缓冲区中的VA地址转化为RVA地址。
	 * @param pPeBuf 指向已加载PE文件的缓冲区的指针。
	 * @param va 待转化的VA地址。
	 * @return 转化后的RVA地址，如果转化失败则为0。
	 */
	static DWORD va2rva(LPBYTE pPeBuf, DWORD va);

	/**
	 * @brief 将指定路径的PE文件中的RVA地址转化为VA地址。
	 * @param path PE文件的路径。
	 * @param rva 待转化的RVA地址。
	 * @return 转化后的VA地址，如果转化失败则为0。
	 */
	static DWORD rva2va(const char* path, DWORD rva);

	/**
	 * @brief 将指定PE文件的缓冲区中的RVA地址转化为VA地址。
	 * @param pPeBuf 指向已加载PE文件的缓冲区的指针。
	 * @param rva 待转化的RVA地址。
	 * @return 转化后的VA地址，如果转化失败则为0。
	 */
	static DWORD rva2va(LPBYTE pPeBuf, DWORD rva);

	/**
	 * @brief 将指定路径的PE文件中的文件偏移地址转化为VA地址。
	 * @param path PE文件的路径。
	 * @param faddr 待转化的文件偏移地址。
	 * @return 转化后的VA地址，如果转化失败则为0。
	 */
	static DWORD faddr2va(const char* path, DWORD faddr);

	/**
	 * @brief 将指定PE文件缓冲区中的文件偏移地址转化为VA地址。
	 * @param pPeBuf 指向已加载PE文件的缓冲区的指针。
	 * @param faddr 待转化的文件偏移地址。
	 * @return 转化后的VA地址，如果转化失败则为0。
	 */
	static DWORD faddr2va(LPBYTE pPeBuf, DWORD faddr);

	/**
	 * @brief 将指定路径的PE文件中的VA地址转化为文件偏移地址。
	 * @param path PE文件的路径。
	 * @param va 待转化的VA地址。
	 * @return 转化后的文件偏移地址，如果转化失败则为0。
	 */
	static DWORD va2faddr(const char* path, DWORD va);

	/**
	 * @brief 将指定PE文件缓冲区中的VA地址转化为文件偏移地址。
	 * @param pPeBuf 指向已加载PE文件的缓冲区的指针。
	 * @param va 待转化的VA地址。
	 * @return 转化后的文件偏移地址，如果转化失败则为0。
	*/
	static DWORD va2faddr(LPBYTE pPeBuf, DWORD va);
protected:
	/* 表示载入的 PE 文件是否为内存对齐 */
	bool m_bMemAlign; 
	/* 表示内存是否是在该类中分配的 */
	bool m_bMemAlloc; 
	/* 存储 PE 文件的路径，使用 MAX_PATH 作为缓冲区大小 */
	char m_szFilePath[MAX_PATH]; 
	/* 指向 PE 文件缓冲区的指针 */
	LPBYTE	m_pPeBuf;		
	/* PE 文件缓冲区的大小 */
	DWORD	m_dwPeBufSize;	
	/* 指向 PE 文件附加数据缓冲区的指针。如果文件是内存对齐的，它将被重新分配；否则，它将指向相应的位置，如果没有附加数据，则为 NULL */
	LPBYTE	m_pOverlayBuf;	
	/* PE 文件附加数据缓冲区的大小 */
	DWORD	m_dwOverlayBufSize;
public:
	PEInfo() {
		iniValue();
	}
	virtual ~PEInfo()
	{
		closePeFile();
	}

	/**
	 * @brief 构造函数：从文件加载 PE 数据到内存。
	 * @param path PE 文件的完整路径。
	 * @param bMemAlign 是否对缓冲区进行内存对齐。默认为 true。
	*/
	PEInfo(const char* path, bool bMemAlign = true);
	/**
	 * @brief 构造函数：将已经加载的 PE 文件缓冲区附加到 PEInfo 对象中。
	 * @param pPeBuf 指向已经加载的 PE 文件缓冲区的指针。
	 * @param filesize PE 文件缓冲区大小（以字节为单位）。
	 * @param bCopyMem 是否在 PEInfo 对象中创建缓冲区副本。
	 * 如果为 true，将为缓冲区分配新的内存并将其副本复制到该内存中。
	 * 如果为 false，则不会为缓冲区分配新内存，并且该缓冲区将在 PEInfo 对象的生命周期中一直有效。
	 * @param bMemAlign 是否对缓冲区进行内存对齐。默认为 true。
	*/
	PEInfo(LPBYTE pPeBuf, DWORD filesize, bool bCopyMem = false, bool bMemAlign = true);
	/**
	 * @brief 将当前 PEInfo 对象的数据复制到另一个 PEInfo 对象中。
	 * @param pe 要将数据复制到的 PEInfo 对象。
	 * @param bCopyMem 是否为新的 PEInfo 对象创建缓冲区副本。默认为 true。
	 */
	void copy(const PEInfo& pe, bool bCopyMem = true);

	/**
	 * @brief 拷贝构造函数：将另一个 PEInfo 对象的数据复制到新创建的 PEInfo 对象中。
	 * @param pe 要复制的 PEInfo 对象。
	 */
	PEInfo(const PEInfo& pe);

	/**
	 * @brief 赋值运算符：将另一个 PEInfo 对象的数据复制到当前 PEInfo 对象中。
	 * @param pe 要复制的 PEInfo 对象。
	 * @return 当前 PEInfo 对象的引用。
	*/
	PEInfo& operator=(PEInfo& pe);


	void iniValue();
	/**
	 * @brief 将一个已经加载的 PE 文件缓冲区附加到 PEInfo 对象中。
	 * @param pPeBuf 指向已经加载的 PE 文件缓冲区的指针。
	 * @param dwFileBufSize PE 文件缓冲区大小（以字节为单位）。
	 * @param bCopyMem 是否在 PEInfo 对象中创建缓冲区副本。
	 *                 如果为 true，将为缓冲区分配新的内存并将其副本复制到该内存中。
	 *                 如果为 false，则不会为缓冲区分配新内存，并且该缓冲区将在 PEInfo 对象的生命周期中一直有效。
	 * @param bMemAlign 是否对缓冲区进行内存对齐。
	 *                 如果为 true，则将缓冲区在内存中对齐，否则不进行内存对齐。
	 * @param pOverlayBuf 指向可选的覆盖区域的指针。如果没有覆盖区域，则可以将其设置为 NULL。
	 * @param dwOverLayBufSize 覆盖区域大小（以字节为单位）。如果没有覆盖区域，则应将其设置为0。
	 * @return 如果 PE 文件缓冲区是有效的 PE 文件，则返回 1；否则返回 0。
	 */
	int attachPeBuf(LPBYTE pPeBuf, DWORD dwFileBufSize, bool isCopyMem = true, bool bMemAlign = true, LPBYTE pOverlayBuf = NULL, DWORD dwOverLayBufSize = 0);

	/**
	 * @brief 关闭 PE 文件并释放相应的资源
	 */
	void closePeFile();

	/**
	 * @brief 判断当前的 PE 文件是否为 PE 格式
	 * @return int 返回 0 表示不是 PE 文件，1 表示是 32 位 PE 文件，2 表示是 64 位 PE 文件
	 */
	int isPe();

	/**
	 * @brief 打开一个PE文件，解析其中的PE头部信息，将PE文件映射到内存中，并返回映射后的大小。
	 * @param path PE文件的路径。
	 * @param bMemAlign 是否按照内存页对齐PE文件。
	 * @return 如果文件打开成功，返回映射后的大小；否则返回负数错误码。
	 */
	DWORD openPeFile(const char* path, bool bMemAlign = true);

	/**
	 * @brief 判断是否内存对齐
	 * @return true表示内存对齐，false表示非内存对齐
	 */
	bool isMemAlign() const; 

	/**
	 * @brief 判断是否为内存分配
	 * @return true表示内存为此处分配的，false表示非内存为此处分配的
	 */
	bool isMemAlloc() const; 
	/**
	 * @brief 返回 PE 文件路径的常量指针。成员函数是一个只读、安全、不修改对象状态的函数
	 * @return PE 文件路径的常量指针。
	 */
	const char* const getFilePath() const;

	/**
	 * @brief 获取PE文件缓冲区指针
	 * @return PE文件缓冲区指针
	 */
	LPBYTE getPeBuf() const;
	/**
	 * @brief 获取PE文件缓冲区大小
	 * @return PE文件缓冲区大小
	 */
	DWORD getPeBufSize() const;

	/**
	 * @brief 获取PE文件内存对齐后的大小
	 * @return DWORD 返回PE文件内存对齐后的大小
	*/
	DWORD getAlignSize() const;

	/**
	 * @brief 将给定的数值按照内存对齐大小对齐
	 * @param num 要对齐的数值
	 * @return DWORD 对齐后的数值
	*/

	DWORD toAlign(DWORD num) const;
	/**
	 * @brief 获取PE文件内存大小
	 * @return DWORD 返回PE文件内存大小
	*/
	DWORD getPeMemSize() const;
	/**
	 * @brief 获取PE附加数据缓冲区指针
	 * @return PE附加数据缓冲区指针
	 */
	LPBYTE getOverlayBuf() const;
	/**
	 * @brief 获取PE附加数据缓冲区大小
	 * @return PE附加数据缓冲区大小
	 */
	DWORD getOverlayBufSize() const;

	/**
	 * @brief 获取PE文件的NT头指针
	 * @return PIMAGE_NT_HEADERS 返回指向PE文件的NT头的指针
	*/
	PIMAGE_NT_HEADERS getNtHeader();

	/**
	 * @brief 获取PE文件的文件头指针
	 * @return PIMAGE_FILE_HEADER 返回指向PE文件的文件头的指针
	*/
	PIMAGE_FILE_HEADER getFileHeader();

	/**
	 * @brief 获取PE文件的可选头指针
	 * @return PIMAGE_OPTIONAL_HEADER 返回指向PE文件的可选头的指针
	*/
	PIMAGE_OPTIONAL_HEADER getOptionalHeader();

	/**
	 * @brief 获取PE文件的数据目录指针
	 * @return PIMAGE_DATA_DIRECTORY 返回指向PE文件的数据目录的指针
	*/
	PIMAGE_DATA_DIRECTORY getImageDataDirectory();

	/**
	 * @brief 获取PE文件的区段头指针
	 * @return PIMAGE_SECTION_HEADER 返回指向PE文件的区段头的指针
	*/
	PIMAGE_SECTION_HEADER getSectionHeader();

	/**
	 * @brief 获取PE文件的导入描述符指针
	 * @return PIMAGE_IMPORT_DESCRIPTOR 返回指向PE文件的导入描述符的指针
	*/
	PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor();

	/**
	 * @brief 获取PE文件的导出目录指针
	 * @return PIMAGE_EXPORT_DIRECTORY 返回指向PE文件的导出目录的指针
	*/
	PIMAGE_EXPORT_DIRECTORY getExportDirectory();

	/**
	 * @brief 获取PE文件的OEP RVA
	 * @return DWORD 返回PE文件的OEP RVA
	*/
	DWORD getOepRva();

	/**
	 * @brief 获取PE文件的区段数
	 * @return WORD 返回PE文件的区段数
	*/
	WORD getSectionNum();

	/**
	 * @brief 查找RVA所在的区段索引
	 * @param rva RVA地址
	 * @return int 返回区段索引，若未找到则返回-1
	*/
	int findRvaSectIdx(DWORD rva);

	/**
	 * @brief 将相对虚拟地址(RVA)转换为文件偏移地址(File Offset)
	 * @param rva 相对虚拟地址
	 * @return DWORD 对应的文件偏移地址
	*/
	DWORD rva2faddr(DWORD rva) const;

	/**
	 * @brief 将文件偏移地址(File Offset)转换为相对虚拟地址(RVA)
	 * @param faddr 文件偏移地址
	 * @return DWORD 对应的相对虚拟地址
	*/
	DWORD faddr2rva(DWORD faddr) const;

	/**
	 * @brief 将虚拟地址(Virtual Address)转换为相对虚拟地址(RVA)
	 * @param va 虚拟地址
	 * @return DWORD 对应的相对虚拟地址
	*/
	DWORD va2rva(DWORD va) const;

	/**
	 * @brief 将相对虚拟地址(RVA)转换为虚拟地址(Virtual Address)
	 * @param rva 相对虚拟地址
	 * @return DWORD 对应的虚拟地址
	*/
	DWORD rva2va(DWORD rva) const;

	/**
	 * @brief 将文件偏移地址(File Offset)转换为虚拟地址(Virtual Address)
	 * @param faddr 文件偏移地址
	 * @return DWORD 对应的虚拟地址
	*/
	DWORD faddr2va(DWORD faddr) const;

	/**
	 * @brief 将虚拟地址(Virtual Address)转换为文件偏移地址(File Offset)
	 * @param va 虚拟地址
	 * @return DWORD 对应的文件偏移地址
	*/
	DWORD va2faddr(DWORD va) const;
private:
};