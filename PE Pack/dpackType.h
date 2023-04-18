#include "../lzmalib/LzmaLib.h"

typedef struct _DLZMA_HEADER
{
	size_t RawDataSize;//原始数据尺寸(不含此头)
	size_t DataSize;//压缩后的数据大小
	unsigned char LzmaProps[LZMA_PROPS_SIZE];//原始lzma的文件头
}DLZMA_HEADER, * PDLZMA_HEADER;//此处外围添加适用于dpack的lzma头