#include "../lzmalib/LzmaLib.h"

typedef struct _DLZMA_HEADER
{
	size_t RawDataSize;//ԭʼ���ݳߴ�(������ͷ)
	size_t DataSize;//ѹ��������ݴ�С
	unsigned char LzmaProps[LZMA_PROPS_SIZE];//ԭʼlzma���ļ�ͷ
}DLZMA_HEADER, * PDLZMA_HEADER;//�˴���Χ���������dpack��lzmaͷ