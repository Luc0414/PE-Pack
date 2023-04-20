#include <Windows.h>
#include "dpackType.h"


/**
 * @brief ��ѹLzmaѹ������
 * @param pDstBuf Ŀ�껺����ָ��
 * @param pSrcBuf ѹ�����ݻ�����ָ��
 * @param srcSize ѹ�����ݴ�С
 * @return ��ѹ������ݴ�С
 */
size_t dlzmaUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	// ��ȡLzmaͷָ��
	PDLZMA_HEADER pdlzmah = (PDLZMA_HEADER)pSrcBuf;
	// ��ȡĿ�껺������С����ԭʼ���ݴ�С
	size_t dstSize = pdlzmah->RawDataSize;
	// ��ѹ����
	LzmaUncompress(pDstBuf, &dstSize, pSrcBuf + sizeof(DLZMA_HEADER), &srcSize, pdlzmah->LzmaProps, LZMA_PROPS_SIZE);
	// ���ؽ�ѹ������ݴ�С
	return dstSize;
}