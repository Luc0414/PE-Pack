#include <Windows.h>
#include "PeEdit.h"
#include <Psapi.h>	



#ifndef _SIMPLEDPACK_H
#define _SIMPLEDPACK_H

typedef struct _DPACK_TMPBUF_ENTRY {
	LPBYTE PackedBuf;
	DWORD DpackSize;
	DWORD OrgRva;
	DWORD OrgMemSize;
	DWORD Characteristics;
}DPACK_TMPBUF_ENTRY, * PDPACK_TMPBUF_ENTRY;

class CSimpleDpack {
public:
	static LPBYTE dlzmaPack(LPBYTE pSrcBuf,size_t srcSize,size_t* pDstSize,double maxmul = 2.0);
	static LPBYTE dlzmaUnpack(LPBYTE pSrcBuf,size_t srcSize);
private:
	char m_strFilePath[MAX_PATH];
protected:

public:

};
#endif