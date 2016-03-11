#include "fs.h"
#include "draw.h"
#include "platform.h"
#include "decryptor/aes.h"
#include "decryptor/decryptor.h"
#include "decryptor/nand.h"
#include "decryptor/otphelper.h"
#include "NCSD_header_o3ds_hdr.h"


static PartitionInfo partition_n3ds =
    { "CTRNFULL", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0x0B930000, 0x41ED0000, 0x5, AES_CNT_CTRNAND_MODE };
    
static PartitionInfo partition_no3ds =
    { "CTRNFULL", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0x0B930000, 0x41ED0000, 0x4, AES_CNT_CTRNAND_MODE };
    
static u8 nand_magic_n3ds[0x60] = {
    0x4E, 0x43, 0x53, 0x44, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x04, 0x03, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00, 0x00, 0x88, 0x05, 0x00, 0x80, 0x01, 0x00, 0x00,
    0x80, 0x89, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80, 0xA9, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00,
    0x80, 0xC9, 0x05, 0x00, 0x80, 0xF6, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static u8 nand_magic_o3ds[0x60] = {
    0x4E, 0x43, 0x53, 0x44, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x04, 0x03, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00, 0x00, 0x88, 0x05, 0x00, 0x80, 0x01, 0x00, 0x00,
    0x80, 0x89, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80, 0xA9, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00,
    0x80, 0xC9, 0x05, 0x00, 0x80, 0xAE, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

u32 CheckNandHeader(u8* header) {
    u8 lheader[0x200];
    
    if (header != NULL) {
        memcpy(lheader, header, 0x200);
    } else {
        ReadNandHeader(lheader);
    }
    
    if (memcmp(lheader + 0x100, nand_magic_n3ds, 0x60) == 0) {
        return NAND_HDR_N3DS;
    } else if (memcmp(lheader + 0x100, nand_magic_o3ds, 0x60) == 0) {
        return NAND_HDR_O3DS;
    } 
    
    return NAND_HDR_UNK;
}

u32 DumpOtp(u32 param)
{
    u32 otpsize = (param & OTP_BIG) ? 0x108 : 0x100;
    Debug("Dumping otp.bin (%u byte)...", otpsize);
    if (!DebugFileCreate((param & OTP_BIG) ? "otp0x108.bin" : "otp.bin", true))
        return 1;
    if (!DebugFileWrite((void*)0x10012000, otpsize, 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    
    return 0;
}

u32 ExpandOtp(u32 param)
{
    u8* buffer = BUFFER_ADDRESS;
    u32* TwlCustId = (u32*) (0x01FFB808);
    u32 FixCustId[2];
    
    if (!DebugFileOpen("otp.bin"))
        return 1;
    if (FileGetSize() != 0x100) {
        FileClose();
        Debug("File has bad size, should be 256 byte");
        return 1;
    }
    if (!DebugFileRead(buffer, 0x100, 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    
    FixCustId[0] = (TwlCustId[0] ^ 0xB358A6AF) | 0x80000000;
    FixCustId[1] = TwlCustId[1] ^ 0x08C267B7;
    
    Debug("TWL Customer ID: %08X%08X", TwlCustId[0], TwlCustId[1]);
    Debug("Fixed version  : %08X%08X", FixCustId[0], FixCustId[1]);
    Debug("Appending fixed TWL customer id...");
    memcpy(buffer + 0x100, (u8*) FixCustId, 8);
    
    if (!DebugFileCreate("otp0x108.bin", true))
        return 1;
    if (!DebugFileWrite(buffer, 0x108, 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    
    return 0;
}

u32 SwitchCtrNandCrypto(u32 param)
{
    u8* buffer = BUFFER_ADDRESS;
    bool to_o3ds = !(param & OTP_TO_N3DS);
    PartitionInfo* partition_from = (to_o3ds) ? &partition_n3ds : &partition_no3ds;
    PartitionInfo* partition_to = (to_o3ds) ? &partition_no3ds : &partition_n3ds;
    
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
        
    if (GetUnitPlatform() != PLATFORM_N3DS) {
        Debug("This feature is intended only for N3DS");
        return 1;
    }
    
    // Encryption magic check
    PartitionInfo p_chk;
    memcpy(&p_chk, GetPartitionInfo(P_CTRNAND), sizeof(PartitionInfo));
    p_chk.keyslot = (to_o3ds) ? 0x5 : 0x4;
    if (DecryptNandToMem(buffer, p_chk.offset, 16, &p_chk) != 0)
        return 1;
    if (memcmp(p_chk.magic, buffer, 8) != 0) {
        Debug("CTRNAND is not slot0x%u encrypted!", p_chk.keyslot);
        return 1;
    }
    
    Debug("Switching CTRNAND partion 0x%u -> 0x%u...", (to_o3ds) ? 5 : 4, (to_o3ds) ? 4 : 5);
    u32 size = partition_from->size;
    u32 offset = partition_from->offset;
    for (u32 i = 0; i < size; i += NAND_SECTOR_SIZE * SECTORS_PER_READ) {
        u32 read_bytes = min(NAND_SECTOR_SIZE * SECTORS_PER_READ, (size - i));
        ShowProgress(i, size);
        DecryptNandToMem(buffer, offset + i, read_bytes, partition_from);
        EncryptMemToNand(buffer, offset + i, read_bytes, partition_to);
    }
    ShowProgress(0, 0);
    
    return 0;
}

u32 DumpNandHeader(u32 param)
{
    u8* header = BUFFER_ADDRESS;
    char filename[32];
    bool is_o3ds;
    
    ReadNandHeader(header);
    u32 nand_hdr_type = CheckNandHeader(header);
    if (nand_hdr_type == NAND_HDR_UNK) {
        Debug("NAND header not recognized!");
        return 1;
    } else {
        is_o3ds = (nand_hdr_type == NAND_HDR_O3DS);
    }
    
    snprintf(filename, 31, "NCSD_header_%s.bin", (is_o3ds) ? "o3ds" : "n3ds");
    if (!DebugFileCreate(filename, true))
        return 1;
    if (!DebugFileWrite(header, 0x200, 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    
    return 0;
}

u32 InjectNandHeader(u32 param)
{
    u8* header = BUFFER_ADDRESS;
    char filename[32];
    bool to_o3ds = !(param & OTP_TO_N3DS);
    
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
        
    if (GetUnitPlatform() != PLATFORM_N3DS) {
        Debug("This feature is intended only for N3DS");
        return 1;
    }
    
    if (!(param & HDR_FROM_MEM)) {
        snprintf(filename, 31, "NCSD_header_%s.bin", (to_o3ds) ? "o3ds" : "n3ds");
        if (!DebugFileOpen(filename)) {
            Debug("This file must be placed on your SD card");
            return 1;
        }
        if (!DebugFileRead(header, 0x200, 0)) {
            FileClose();
            return 1;
        }
        FileClose();
    } else {
        if (!to_o3ds) {
            Debug("You need to provide NCSD_header_n3ds.bin");
            return 1;
        }
        if (NCSD_header_o3ds_hdr_size != 0x200) {
            Debug("NCSD_header_o3ds bad size: %i", NCSD_header_o3ds_hdr_size);
            return 1;
        }
        memcpy(header, NCSD_header_o3ds_hdr, 0x200);
    }
    
    u32 nand_hdr_type = CheckNandHeader(header);
    if (to_o3ds && (nand_hdr_type != NAND_HDR_O3DS)) {
        Debug("O3DS NAND header not recognized");
        return 1;
    } else if (!to_o3ds && (nand_hdr_type != NAND_HDR_N3DS)) {
        Debug("N3DS NAND header not recognized");
        return 1;
    }
    
    Debug("Injecting NAND header...");
    WriteNandHeader(header);
    
    return 0;
}

u32 UnbrickNand(u32 param)
{   
    // switch CTRNAND crypto
    if (SwitchCtrNandCrypto(param) != 0)
        return 1;
    
    // inject NAND header
    if (InjectNandHeader(param) != 0)
        return 1;
    
    return 0;
}
