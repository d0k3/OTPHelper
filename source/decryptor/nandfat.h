#pragma once

#include "decryptor/nand.h"
#include "common.h"

#define S_TITLE_FOUND     0
#define S_TMD_NOT_FOUND   1
#define S_TMD_IS_CORRUPT  1
#define S_APP_NOT_FOUND   2

u32 SeekFileInNand(u32* offset, u32* size, const char* path, PartitionInfo* partition);
u32 SeekTitleInNandDb(u32* tmd_id, u64 titleId);
u32 SeekTitleInNand(u32* offset_tmd, u32* size_tmd, u32* offset_app, u32* size_app, u64 titleId, u32 max_cnt);
