#pragma once

#include "common.h"

#define OTP_BIG         (1<<0)
#define OTP_TO_O3DS     (1<<1)
#define OTP_TO_N3DS     0

// return values for NAND header check
#define NAND_HDR_UNK    0
#define NAND_HDR_O3DS   1
#define NAND_HDR_N3DS   2

u32 CheckNandHeader(u8* header);

// --> FEATURE FUNCTIONS <--
u32 DumpOtp(u32 param);
u32 SwitchCtrNandCrypto(u32 param);
u32 DumpNandHeader(u32 param);
u32 InjectNandHeader(u32 param);
