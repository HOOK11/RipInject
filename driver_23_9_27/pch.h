#pragma once
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <intrin.h>

#include "NtStruct.h"
#include "oxygenPdb.h"
#include "util.h"
#include "ShellCode.h"

#include "memory.h"


#ifdef DBG
#define DbgBreak __debugbreak
#else
#define DbgBreak()
#endif // DEBUG

