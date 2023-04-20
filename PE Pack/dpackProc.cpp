#include <Windows.h>
#include "dpackType.h"

/**
 * @brief ʹ��LZMA�㷨���������ݽ���ѹ��
 * @param pDstBuf ѹ�������ݴ�ŵ�Ŀ�껺����ָ��
 * @param pSrcBuf ��Ҫѹ����ԭʼ���ݻ�����ָ��
 * @param srcSize ��Ҫѹ����ԭʼ���ݴ�С����λ���ֽڣ�
 * @return ����ѹ��������ݴ�С����λ���ֽڣ�
*/
size_t dlzmaPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	size_t dstSize = -1;
	size_t propSize = sizeof(DLZMA_HEADER);
	PDLZMA_HEADER pDlzmah = (PDLZMA_HEADER)pDstBuf;
	LzmaCompress(pDstBuf + sizeof(DLZMA_HEADER), &dstSize, pSrcBuf, srcSize, pDlzmah->LzmaProps, (size_t*)&propSize, -1, 0, -1, -1, -1, -1, -1);
	pDlzmah->RawDataSize = srcSize;
	pDlzmah->DataSize = dstSize;
	return dstSize;
}