#pragma once

#include "PEInfo.h"
#ifndef _PEEDIT_H
#define _PEEDIT_H

/* ผฬณะ PEInfo */
class PEedit :public PEInfo {

public:
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);
	static DWORD setOepRva(const char * path,DWORD RVA);
	static DWORD setOepRva(LPBYTE pPeBuf, DWORD RVA);
public:

};

#endif