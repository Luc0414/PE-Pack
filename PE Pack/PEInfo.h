#pragma once
#include <Windows.h>


#define PEHBUF_SIZE 0X500

typedef struct {
	WORD Offset : 12;  //ƫ��ֵ
	WORD type : 4;  //�ض�λ����(��ʽ)
} RELOCOFFSET,* PRELOCOFFSET;

class PEInfo {
public:

	//�ļ�����

	/**
	 * @brief ��ȡָ���ļ��Ĵ�С��
	 * @param path �ļ�·����
	 * @return �ļ��Ĵ�С����λ���ֽڣ���
	 */
	static DWORD GetFileSize(const char* path);

	/**
	 * @brief ��ȡָ����С�����ݿ鵽�ڴ��С�
	 * @param path �ļ�·����
	 * @param pFileBuf ָ��洢��ȡ���ݵĻ�������ָ�롣
	 * @param size Ҫ��ȡ�����ݴ�С����λ���ֽڣ���
	 * @return ʵ�ʶ�ȡ�����ݴ�С����λ���ֽڣ���
	 */
	static DWORD readFile(const char* path, LPBYTE pFileBuf, DWORD size);

	/**
	 * @brief ��һ��PE�ļ��Ӵ��̼��ص��ڴ��У�����ѡ���ڴ沼�����ļ����ֶ��롣
	 * @param path PE�ļ���·����
	 * @param pPeBuf ָ��洢���ص�PE�ļ��Ļ�������ָ�롣
	 * @param FileBufSize (��ѡ) һ��ָ��DWORD��ָ�룬����������Ϊ���ص�PE�ļ��Ĵ�С��
	 * @param bMemAlign ���Ϊ�棬PE�ļ������ڴ沼�ֶ��룬���򽫰��ļ����ֶ��롣
	 * @param pOverlayBuf (optional) һ��ָ�򻺳�����ָ�룬PE�ļ���������ݽ����洢���������еĻ�����
	 * @param OverlayBufSize (optional) һ��ָ��DWORD��ָ�룬��ָ�뽫������ΪPE�ļ�������ݵĴ�С������еĻ�����
	 * @return ���ص�PE�ļ��Ĵ�С���������ʧ����Ϊ0��
	 */
	static DWORD loadPeFile(const char* path, LPBYTE pPeBuf, DWORD* FileBufSize, bool bMemAlign, LPBYTE pOverlayBuf, DWORD* OverlayBufSize);

	/**
	 * @brief �ж�һ���ڴ滺�����Ƿ�ΪPE��ʽ��
	 * @param pPeBuf ָ��PE�ļ���������ָ�롣
	 * @return �����������PE�ļ���ʽ���򷵻�1�����򷵻�0��
	 */
	static int isPe(LPBYTE pPeBuf);

	/**
	 * @brief �ж�һ���ļ��Ƿ�ΪPE��ʽ��
	 * @param path �ļ�·����
	 * @return ����ļ���PE�ļ���ʽ���򷵻�1�����򷵻�0��
	 */
	static int isPe(const char* path);

	/**
	 * @brief ������������ָ���Ķ��뷽ʽ����
	 * @param num ���������
	 * @param align ���뷽ʽ
	 * @return ��������
	*/
	static DWORD toAlign(DWORD num, DWORD align);


	// static pe ������ȡ
	/**
	 * @brief ��ȡPE�ļ���NTͷ��
	 * @param pPeBuf ָ��PE�ļ���������ָ�롣
	 * @return ָ��PE�ļ�NTͷ��ָ�롣
	 */
	static PIMAGE_NT_HEADERS GetNtHeader(LPBYTE pPeBuf);

	/**
	 * @brief ��ȡPE�ļ����ļ�ͷ��
	 * @param pPeBuf ָ��PE�ļ���������ָ�롣
	 * @return ָ��PE�ļ��ļ�ͷ��ָ�롣
	 */
	static PIMAGE_FILE_HEADER GetFileHeader(LPBYTE pPeBuf);

	/**
	 * @brief ��ȡPE�ļ��Ŀ�ѡͷ��
	 * @param pPeBuf ָ��PE�ļ���������ָ�롣
	 * @return ָ��PE�ļ���ѡͷ��ָ�롣
	 */
	static PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPBYTE pPeBuf);

	/**
	 * @brief ��ȡPE�ļ�������Ŀ¼��
	 * @param pPeBuf ָ��PE�ļ���������ָ�롣
	 * @return ָ��PE�ļ�����Ŀ¼��ָ�롣
	 */
	static PIMAGE_DATA_DIRECTORY GetImageDataDirectory(LPBYTE pPeBuf);

	/**
	 * @brief ��ȡPE�ļ��Ľڱ�
	 * @param pPeBuf ָ��PE�ļ���������ָ�롣
	 * @return ָ��PE�ļ��ڱ��ָ�롣
	 */
	static PIMAGE_SECTION_HEADER GetSectionHeader(LPBYTE pPeBuf);

	/**
	 * @brief ��ȡPE�ļ��еĵ�����������
	 * @param pPeBuf ָ��PE�ļ���ָ�롣
	 * @param bMemAlign ���Ϊtrue����ƫ�������ڴ���룬�����ļ����롣
	 * @return ָ�������������ָ�롣
	 */
	static PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(LPBYTE pPeBuf, bool bFromFile);

	/**
	 * @brief ��ȡPE�ļ��еĵ�����������
	 * @param pPeBuf ָ��PE�ļ���ָ�롣
	 * @param bMemAlign ���Ϊtrue����ƫ�������ڴ���룬�����ļ����롣
	 * @return ָ�򵼳����������ָ�롣
	 */
	static PIMAGE_EXPORT_DIRECTORY getExportDirectory(LPBYTE pPeBuf, bool bFromFile);

	/**
	 * @brief ��ȡPE�ļ���ڵ�RVA
	 * @param path PE�ļ�·��
	 * @return PE�ļ���ڵ�RVA
	 */
	static DWORD GetOEPRVA(const char* path);

	/**
	 * @brief ��ȡPE�ļ���ڵ�RVA
	 * @param pPeBuf PE�ļ��ڴ滺����ָ��
	 * @return PE�ļ���ڵ�RVA
	 */
	static DWORD GetOEPRVA(LPBYTE pPeBuf);

	/**
	 * @brief ��ȡPE�ļ��ڱ�����
	 * @param pPeBuf PE�ļ��ڴ滺����ָ��
	 * @return PE�ļ��ڱ�����
	 */
	static WORD GetSectionNum(LPBYTE pPeBuf);

	/**
	 * @brief ����ָ��RVA���ڵĽڱ����
	 * @param pPeBuf PE�ļ��ڴ滺����ָ��
	 * @param rva Ҫ���ҵ�RVA
	 * @return ����ҵ��򷵻ؽڱ���ţ����򷵻�-1
	 */
	static int FindRvaSectIdx(LPBYTE pPeBuf, DWORD rva);

	/**
	 * @brief ��ȡPE�ļ����ڴ������������С
	 * @param path PE�ļ�·��
	 * @return DWORD PE�ļ����ڴ������������С�����ֽ�Ϊ��λ
	 */
	static DWORD GetPeMemSize(const char* path);

	/**
	 * @brief ��ȡPE�ļ����ڴ������������С
	 * @param pPeBuf ָ��PE�ļ����ݻ�������ָ��
	 * @return DWORD PE�ļ����ڴ������������С�����ֽ�Ϊ��λ
	*/
	static DWORD GetPeMemSize(LPBYTE pPeBuf);

	/**
	 * @brief ��ȡPE�ļ��ĸ������ݴ�С
	 * @param path PE�ļ�·��
	 * @return DWORD PE�ļ��ĸ������ݴ�С�����ֽ�Ϊ��λ�����޸��������򷵻�0
	 */
	static DWORD GetOverlaySize(const char* path);

	/**
	 * @brief ��ȡPE�ļ��ĸ������ݴ�С
	 * @param pFileBuf ָ��PE�ļ����ݻ�������ָ��
	 * @param dwFileSize PE�ļ����ݻ�������С�����ֽ�Ϊ��λ
	 * @return DWORD PE�ļ��ĸ������ݴ�С�����ֽ�Ϊ��λ�����޸��������򷵻�0
	 */
	static DWORD GetOverlaySize(LPBYTE pFileBuf, DWORD dwFileSize);

	/**
	 * @brief ��ȡPE�ļ��ĸ�������
	 * @param path PE�ļ�·��
	 * @param pOverlay ָ��洢PE�ļ��������ݵĻ�������ָ��
	 * @return DWORD ��ȡ��PE�ļ��������ݴ�С�����ֽ�Ϊ��λ�����޸��������򷵻�0
	 */
	static DWORD readOverlay(const char* path, LPBYTE pOverlay);

	/**
	 * @brief ��ȡPE�ļ��ĸ�������
	 * @param pFileBuf ָ��PE�ļ����ݻ�������ָ��
	 * @param dwFileSize PE�ļ����ݻ�������С�����ֽ�Ϊ��λ
	 * @param pOverlay ָ��洢PE�ļ��������ݵĻ�������ָ��
	 * @return DWORD ��ȡ��PE�ļ��������ݴ�С�����ֽ�Ϊ��λ�����޸��������򷵻�0
	*/
	static DWORD readOverlay(LPBYTE pFileBuf, DWORD dwFileSize, LPBYTE pOverlay);

	// ��ַת������
	/**
	 * @brief ��PE�ļ���RVA��ַת��Ϊ�ļ�ƫ�Ƶ�ַ
	 * @param path PE�ļ���·��
	 * @param rva ��ת����RVA��ַ
	 * @return ת������ļ�ƫ�Ƶ�ַ�����ת��ʧ����Ϊ0
	 */
	static DWORD rva2faddr(const char* path, DWORD rva);

	/**
	 * @brief ��PE�ļ���RVA��ַת��Ϊ�ļ�ƫ�Ƶ�ַ��
	 * @param pPeBuf ָ���Ѽ���PE�ļ��Ļ�������ָ�롣
	 * @param rva ��ת����RVA��ַ��
	 * @return ת������ļ�ƫ�Ƶ�ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD rva2faddr(LPBYTE pPeBuf, DWORD rva);

	/**
	 * @brief ���ļ�ƫ�Ƶ�ַת��ΪPE�ļ��е�RVA��ַ��
	 * @param path PE�ļ���·����
	 * @param faddr ��ת�����ļ�ƫ�Ƶ�ַ��
	 * @return ת�����RVA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD faddr2rva(const char* path, DWORD faddr);

	/**
	 * @brief ��PE�ļ��е��ļ�ƫ�Ƶ�ַת��ΪRVA��ַ��
	 * @param pPeBuf ָ���Ѽ���PE�ļ��Ļ�������ָ�롣
	 * @param faddr ��ת�����ļ�ƫ�Ƶ�ַ��
	 * @return ת�����RVA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD faddr2rva(LPBYTE pPeBuf, DWORD faddr);

	/**
	 * @brief ��ָ��·����PE�ļ��е�VA��ַת��ΪRVA��ַ��
	 * @param path PE�ļ���·����
	 * @param va ��ת����VA��ַ��
	 * @return ת�����RVA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD va2rva(const char* path, DWORD va);

	/**
	 * @brief ��ָ��PE�ļ��Ļ������е�VA��ַת��ΪRVA��ַ��
	 * @param pPeBuf ָ���Ѽ���PE�ļ��Ļ�������ָ�롣
	 * @param va ��ת����VA��ַ��
	 * @return ת�����RVA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD va2rva(LPBYTE pPeBuf, DWORD va);

	/**
	 * @brief ��ָ��·����PE�ļ��е�RVA��ַת��ΪVA��ַ��
	 * @param path PE�ļ���·����
	 * @param rva ��ת����RVA��ַ��
	 * @return ת�����VA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD rva2va(const char* path, DWORD rva);

	/**
	 * @brief ��ָ��PE�ļ��Ļ������е�RVA��ַת��ΪVA��ַ��
	 * @param pPeBuf ָ���Ѽ���PE�ļ��Ļ�������ָ�롣
	 * @param rva ��ת����RVA��ַ��
	 * @return ת�����VA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD rva2va(LPBYTE pPeBuf, DWORD rva);

	/**
	 * @brief ��ָ��·����PE�ļ��е��ļ�ƫ�Ƶ�ַת��ΪVA��ַ��
	 * @param path PE�ļ���·����
	 * @param faddr ��ת�����ļ�ƫ�Ƶ�ַ��
	 * @return ת�����VA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD faddr2va(const char* path, DWORD faddr);

	/**
	 * @brief ��ָ��PE�ļ��������е��ļ�ƫ�Ƶ�ַת��ΪVA��ַ��
	 * @param pPeBuf ָ���Ѽ���PE�ļ��Ļ�������ָ�롣
	 * @param faddr ��ת�����ļ�ƫ�Ƶ�ַ��
	 * @return ת�����VA��ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD faddr2va(LPBYTE pPeBuf, DWORD faddr);

	/**
	 * @brief ��ָ��·����PE�ļ��е�VA��ַת��Ϊ�ļ�ƫ�Ƶ�ַ��
	 * @param path PE�ļ���·����
	 * @param va ��ת����VA��ַ��
	 * @return ת������ļ�ƫ�Ƶ�ַ�����ת��ʧ����Ϊ0��
	 */
	static DWORD va2faddr(const char* path, DWORD va);

	/**
	 * @brief ��ָ��PE�ļ��������е�VA��ַת��Ϊ�ļ�ƫ�Ƶ�ַ��
	 * @param pPeBuf ָ���Ѽ���PE�ļ��Ļ�������ָ�롣
	 * @param va ��ת����VA��ַ��
	 * @return ת������ļ�ƫ�Ƶ�ַ�����ת��ʧ����Ϊ0��
	*/
	static DWORD va2faddr(LPBYTE pPeBuf, DWORD va);
protected:
	/* ��ʾ����� PE �ļ��Ƿ�Ϊ�ڴ���� */
	bool m_bMemAlign; 
	/* ��ʾ�ڴ��Ƿ����ڸ����з���� */
	bool m_bMemAlloc; 
	/* �洢 PE �ļ���·����ʹ�� MAX_PATH ��Ϊ��������С */
	char m_szFilePath[MAX_PATH]; 
	/* ָ�� PE �ļ���������ָ�� */
	LPBYTE	m_pPeBuf;		
	/* PE �ļ��������Ĵ�С */
	DWORD	m_dwPeBufSize;	
	/* ָ�� PE �ļ��������ݻ�������ָ�롣����ļ����ڴ����ģ����������·��䣻��������ָ����Ӧ��λ�ã����û�и������ݣ���Ϊ NULL */
	LPBYTE	m_pOverlayBuf;	
	/* PE �ļ��������ݻ������Ĵ�С */
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
	 * @brief ���캯�������ļ����� PE ���ݵ��ڴ档
	 * @param path PE �ļ�������·����
	 * @param bMemAlign �Ƿ�Ի����������ڴ���롣Ĭ��Ϊ true��
	*/
	PEInfo(const char* path, bool bMemAlign = true);
	/**
	 * @brief ���캯�������Ѿ����ص� PE �ļ����������ӵ� PEInfo �����С�
	 * @param pPeBuf ָ���Ѿ����ص� PE �ļ���������ָ�롣
	 * @param filesize PE �ļ���������С�����ֽ�Ϊ��λ����
	 * @param bCopyMem �Ƿ��� PEInfo �����д���������������
	 * ���Ϊ true����Ϊ�����������µ��ڴ沢���丱�����Ƶ����ڴ��С�
	 * ���Ϊ false���򲻻�Ϊ�������������ڴ棬���Ҹû��������� PEInfo ���������������һֱ��Ч��
	 * @param bMemAlign �Ƿ�Ի����������ڴ���롣Ĭ��Ϊ true��
	*/
	PEInfo(LPBYTE pPeBuf, DWORD filesize, bool bCopyMem = false, bool bMemAlign = true);
	/**
	 * @brief ����ǰ PEInfo ��������ݸ��Ƶ���һ�� PEInfo �����С�
	 * @param pe Ҫ�����ݸ��Ƶ��� PEInfo ����
	 * @param bCopyMem �Ƿ�Ϊ�µ� PEInfo ���󴴽�������������Ĭ��Ϊ true��
	 */
	void copy(const PEInfo& pe, bool bCopyMem = true);

	/**
	 * @brief �������캯��������һ�� PEInfo ��������ݸ��Ƶ��´����� PEInfo �����С�
	 * @param pe Ҫ���Ƶ� PEInfo ����
	 */
	PEInfo(const PEInfo& pe);

	/**
	 * @brief ��ֵ�����������һ�� PEInfo ��������ݸ��Ƶ���ǰ PEInfo �����С�
	 * @param pe Ҫ���Ƶ� PEInfo ����
	 * @return ��ǰ PEInfo ��������á�
	*/
	PEInfo& operator=(PEInfo& pe);


	void iniValue();
	/**
	 * @brief ��һ���Ѿ����ص� PE �ļ����������ӵ� PEInfo �����С�
	 * @param pPeBuf ָ���Ѿ����ص� PE �ļ���������ָ�롣
	 * @param dwFileBufSize PE �ļ���������С�����ֽ�Ϊ��λ����
	 * @param bCopyMem �Ƿ��� PEInfo �����д���������������
	 *                 ���Ϊ true����Ϊ�����������µ��ڴ沢���丱�����Ƶ����ڴ��С�
	 *                 ���Ϊ false���򲻻�Ϊ�������������ڴ棬���Ҹû��������� PEInfo ���������������һֱ��Ч��
	 * @param bMemAlign �Ƿ�Ի����������ڴ���롣
	 *                 ���Ϊ true���򽫻��������ڴ��ж��룬���򲻽����ڴ���롣
	 * @param pOverlayBuf ָ���ѡ�ĸ��������ָ�롣���û�и�����������Խ�������Ϊ NULL��
	 * @param dwOverLayBufSize ���������С�����ֽ�Ϊ��λ�������û�и���������Ӧ��������Ϊ0��
	 * @return ��� PE �ļ�����������Ч�� PE �ļ����򷵻� 1�����򷵻� 0��
	 */
	int attachPeBuf(LPBYTE pPeBuf, DWORD dwFileBufSize, bool isCopyMem = true, bool bMemAlign = true, LPBYTE pOverlayBuf = NULL, DWORD dwOverLayBufSize = 0);

	/**
	 * @brief �ر� PE �ļ����ͷ���Ӧ����Դ
	 */
	void closePeFile();

	/**
	 * @brief �жϵ�ǰ�� PE �ļ��Ƿ�Ϊ PE ��ʽ
	 * @return int ���� 0 ��ʾ���� PE �ļ���1 ��ʾ�� 32 λ PE �ļ���2 ��ʾ�� 64 λ PE �ļ�
	 */
	int isPe();

	/**
	 * @brief ��һ��PE�ļ����������е�PEͷ����Ϣ����PE�ļ�ӳ�䵽�ڴ��У�������ӳ���Ĵ�С��
	 * @param path PE�ļ���·����
	 * @param bMemAlign �Ƿ����ڴ�ҳ����PE�ļ���
	 * @return ����ļ��򿪳ɹ�������ӳ���Ĵ�С�����򷵻ظ��������롣
	 */
	DWORD openPeFile(const char* path, bool bMemAlign = true);

	/**
	 * @brief �ж��Ƿ��ڴ����
	 * @return true��ʾ�ڴ���룬false��ʾ���ڴ����
	 */
	bool isMemAlign() const; 

	/**
	 * @brief �ж��Ƿ�Ϊ�ڴ����
	 * @return true��ʾ�ڴ�Ϊ�˴�����ģ�false��ʾ���ڴ�Ϊ�˴������
	 */
	bool isMemAlloc() const; 
	/**
	 * @brief ���� PE �ļ�·���ĳ���ָ�롣��Ա������һ��ֻ������ȫ�����޸Ķ���״̬�ĺ���
	 * @return PE �ļ�·���ĳ���ָ�롣
	 */
	const char* const getFilePath() const;

	/**
	 * @brief ��ȡPE�ļ�������ָ��
	 * @return PE�ļ�������ָ��
	 */
	LPBYTE getPeBuf() const;
	/**
	 * @brief ��ȡPE�ļ���������С
	 * @return PE�ļ���������С
	 */
	DWORD getPeBufSize() const;

	/**
	 * @brief ��ȡPE�ļ��ڴ�����Ĵ�С
	 * @return DWORD ����PE�ļ��ڴ�����Ĵ�С
	*/
	DWORD getAlignSize() const;

	/**
	 * @brief ����������ֵ�����ڴ�����С����
	 * @param num Ҫ�������ֵ
	 * @return DWORD ��������ֵ
	*/

	DWORD toAlign(DWORD num) const;
	/**
	 * @brief ��ȡPE�ļ��ڴ��С
	 * @return DWORD ����PE�ļ��ڴ��С
	*/
	DWORD getPeMemSize() const;
	/**
	 * @brief ��ȡPE�������ݻ�����ָ��
	 * @return PE�������ݻ�����ָ��
	 */
	LPBYTE getOverlayBuf() const;
	/**
	 * @brief ��ȡPE�������ݻ�������С
	 * @return PE�������ݻ�������С
	 */
	DWORD getOverlayBufSize() const;

	/**
	 * @brief ��ȡPE�ļ���NTͷָ��
	 * @return PIMAGE_NT_HEADERS ����ָ��PE�ļ���NTͷ��ָ��
	*/
	PIMAGE_NT_HEADERS getNtHeader();

	/**
	 * @brief ��ȡPE�ļ����ļ�ͷָ��
	 * @return PIMAGE_FILE_HEADER ����ָ��PE�ļ����ļ�ͷ��ָ��
	*/
	PIMAGE_FILE_HEADER getFileHeader();

	/**
	 * @brief ��ȡPE�ļ��Ŀ�ѡͷָ��
	 * @return PIMAGE_OPTIONAL_HEADER ����ָ��PE�ļ��Ŀ�ѡͷ��ָ��
	*/
	PIMAGE_OPTIONAL_HEADER getOptionalHeader();

	/**
	 * @brief ��ȡPE�ļ�������Ŀ¼ָ��
	 * @return PIMAGE_DATA_DIRECTORY ����ָ��PE�ļ�������Ŀ¼��ָ��
	*/
	PIMAGE_DATA_DIRECTORY getImageDataDirectory();

	/**
	 * @brief ��ȡPE�ļ�������ͷָ��
	 * @return PIMAGE_SECTION_HEADER ����ָ��PE�ļ�������ͷ��ָ��
	*/
	PIMAGE_SECTION_HEADER getSectionHeader();

	/**
	 * @brief ��ȡPE�ļ��ĵ���������ָ��
	 * @return PIMAGE_IMPORT_DESCRIPTOR ����ָ��PE�ļ��ĵ�����������ָ��
	*/
	PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor();

	/**
	 * @brief ��ȡPE�ļ��ĵ���Ŀ¼ָ��
	 * @return PIMAGE_EXPORT_DIRECTORY ����ָ��PE�ļ��ĵ���Ŀ¼��ָ��
	*/
	PIMAGE_EXPORT_DIRECTORY getExportDirectory();

	/**
	 * @brief ��ȡPE�ļ���OEP RVA
	 * @return DWORD ����PE�ļ���OEP RVA
	*/
	DWORD getOepRva();

	/**
	 * @brief ��ȡPE�ļ���������
	 * @return WORD ����PE�ļ���������
	*/
	WORD getSectionNum();

	/**
	 * @brief ����RVA���ڵ���������
	 * @param rva RVA��ַ
	 * @return int ����������������δ�ҵ��򷵻�-1
	*/
	int findRvaSectIdx(DWORD rva);

	/**
	 * @brief ����������ַ(RVA)ת��Ϊ�ļ�ƫ�Ƶ�ַ(File Offset)
	 * @param rva ��������ַ
	 * @return DWORD ��Ӧ���ļ�ƫ�Ƶ�ַ
	*/
	DWORD rva2faddr(DWORD rva) const;

	/**
	 * @brief ���ļ�ƫ�Ƶ�ַ(File Offset)ת��Ϊ��������ַ(RVA)
	 * @param faddr �ļ�ƫ�Ƶ�ַ
	 * @return DWORD ��Ӧ����������ַ
	*/
	DWORD faddr2rva(DWORD faddr) const;

	/**
	 * @brief �������ַ(Virtual Address)ת��Ϊ��������ַ(RVA)
	 * @param va �����ַ
	 * @return DWORD ��Ӧ����������ַ
	*/
	DWORD va2rva(DWORD va) const;

	/**
	 * @brief ����������ַ(RVA)ת��Ϊ�����ַ(Virtual Address)
	 * @param rva ��������ַ
	 * @return DWORD ��Ӧ�������ַ
	*/
	DWORD rva2va(DWORD rva) const;

	/**
	 * @brief ���ļ�ƫ�Ƶ�ַ(File Offset)ת��Ϊ�����ַ(Virtual Address)
	 * @param faddr �ļ�ƫ�Ƶ�ַ
	 * @return DWORD ��Ӧ�������ַ
	*/
	DWORD faddr2va(DWORD faddr) const;

	/**
	 * @brief �������ַ(Virtual Address)ת��Ϊ�ļ�ƫ�Ƶ�ַ(File Offset)
	 * @param va �����ַ
	 * @return DWORD ��Ӧ���ļ�ƫ�Ƶ�ַ
	*/
	DWORD va2faddr(DWORD va) const;
private:
};