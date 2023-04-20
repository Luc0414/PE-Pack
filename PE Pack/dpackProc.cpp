#include <Windows.h>
#include "dpackType.h"

// ʹ��Lzmaѹ���㷨��Դ���ݽ���ѹ������ѹ�����д��Ŀ�껺����
// ������
//    pDstBuf - Ŀ�껺����
//    pSrcBuf - Դ���ݻ�����
//    srcSize - Դ���ݻ�������С
// ����ֵ��
//    ����ѹ��������ݴ�С
size_t dlzmaPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	// Ŀ�껺������С����ʼ��Ϊ-1����ʾ��󻺳�����С
	size_t dstSize = -1;
	// Lzmaѹ��������С����ʼ��Ϊdpack��Lzmaͷ��С
	size_t propSize = sizeof(DLZMA_HEADER);
	// ��ȡĿ�껺������Lzmaͷָ��
	PDLZMA_HEADER pDlzmah = (PDLZMA_HEADER)pDstBuf;
	// ����Lzmaѹ����������ѹ��
	LzmaCompress(pDstBuf + sizeof(DLZMA_HEADER), &dstSize, pSrcBuf, srcSize, pDlzmah->LzmaProps, (size_t*)&propSize, -1, 0, -1, -1, -1, -1, -1);
	// ����Lzmaͷ�е�ԭʼ���ݴ�С
	pDlzmah->RawDataSize = srcSize;
	// ����Lzmaͷ�е�ѹ�������ݴ�С
	pDlzmah->DataSize = dstSize;
	// ����ѹ��������ݴ�С
	return dstSize;
}