#include "../lzmalib/LzmaLib.h"


#define MAX_DPACKSECTNUM 16 // ����pack��������
#define DPACK_SECTION_RAW 0
#define DPACK_SECTION_DLZMA 1

typedef struct _DLZMA_HEADER
{
	size_t RawDataSize;//ԭʼ���ݳߴ�(������ͷ)
	size_t DataSize;//ѹ��������ݴ�С
	unsigned char LzmaProps[LZMA_PROPS_SIZE];//ԭʼlzma���ļ�ͷ
}DLZMA_HEADER, * PDLZMA_HEADER;//�˴���Χ���������dpack��lzmaͷ


/**
 * @brief ʹ��LZMA�㷨���������ݽ���ѹ��
 * @param pDstBuf ѹ�������ݴ�ŵ�Ŀ�껺����ָ��
 * @param pSrcBuf ��Ҫѹ����ԭʼ���ݻ�����ָ��
 * @param srcSize ��Ҫѹ����ԭʼ���ݴ�С����λ���ֽڣ�
 * @return ����ѹ��������ݴ�С����λ���ֽڣ�
*/
size_t dlzmaPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);

/**
 * @brief ��ѹLzmaѹ������
 * @param pDstBuf Ŀ�껺����ָ��
 * @param pSrcBuf ѹ�����ݻ�����ָ��
 * @param srcSize ѹ�����ݴ�С
 * @return ��ѹ������ݴ�С
 */
size_t dlzmaUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);

typedef struct _DPACK_SHELL_INDEX //DPACK�任ͷ
{
	union
	{
		PVOID DpackOepFunc;  // ��ʼ���ǵ���ں������ŵ�һ��Ԫ�ط����ʼ����
		DWORD DpackOepRva;  // ����shellcode��Ҳ��ĳ����RVA
	};
	DPACK_ORGPE_INDEX OrgIndex;
	WORD SectionNum;									//�任�������������MAX_DPACKSECTNUM����
	DPACK_SECTION_ENTRY SectionIndex[MAX_DPACKSECTNUM];		//�任��������, ��ȫ0��β
	PVOID Extra;
}DPACK_SHELL_INDEX, * PDPACK_SHELL_INDEX;