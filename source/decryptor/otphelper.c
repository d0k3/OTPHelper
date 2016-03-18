#include "fs.h"
#include "draw.h"
#include "hid.h"
#include "platform.h"
#include "decryptor/aes.h"
#include "decryptor/decryptor.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"
#include "decryptor/otphelper.h"
#include "NCSD_header_o3ds_hdr.h"
#include "EUR_sha256.h"
#include "USA_sha256.h"
#include "JAP_sha256.h"

typedef struct {
    u64 titleId;
    u8  reserved[8];
    u8  sha256[32];
} __attribute__((packed)) TitleHashInfo;

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

static u8 firm21_sha256[0x20] = {
    0x87, 0xEF, 0x62, 0x94, 0xB9, 0x95, 0x52, 0x0F, 0xE5, 0x4C, 0x75, 0xCB, 0x6B, 0x17, 0xE0, 0x4A,
    0x6C, 0x3D, 0xE3, 0x26, 0xDB, 0x08, 0xFC, 0x93, 0x39, 0x45, 0xC0, 0x06, 0x51, 0x45, 0x5A, 0x89
}
static u32 firm21_size = 0x000DB000;

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

u32 CheckOtp(u32 param)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 otpsize = (param & OTP_BIG) ? 0x108 : 0x100;
    Debug("Validating otp.bin (%u byte)...", otpsize);
    if (!DebugFileOpen((param & OTP_BIG) ? "otp0x108.bin" : "otp.bin"))
        return 1;
    if (!DebugFileRead(buffer, otpsize, 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    
    // zero check
    u32 zero_chk = 0;
    for (; (zero_chk < otpsize) && (buffer[zero_chk] == 0x00); zero_chk++);
    if (zero_chk >= otpsize) {
        Debug("Your otp dump is all zeroes!");
        return 1;
    }
    
    // comparing with data from memory
    if (memcmp((void*)0x10012000, buffer, otpsize) != 0) {
        Debug("Data does not match with otp!");
        return 1;
    }
    
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

u32 ValidateDowngrade(u32 param)
{
    const u32 max_num_apps = 8;
    
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    PartitionInfo* firm0_info = GetPartitionInfo(P_FIRM0);
    
    TitleHashInfo* checklist = NULL;
    u32 n_titles = 0;
    
    u32 n_full_success = 0;
    u32 n_tmd_success = 0;
    u32 n_skipped = 0;
    u32 n_not_found = 0;
    u32 n_not_matched = 0;
    u32 n_app_not_found = 0;
    u32 n_app_not_matched = 0;
    
    u8  l_sha256[32];
    u32 offset;
    u32 size;
    
    
    // check if unbricked
    if (CheckNandHeader(NULL) == NAND_HDR_N3DS) {
        Debug("NAND is not downgraded or stil bricked");
        return 1;
    }
    
    // perform basic NAND validation
    if (CheckNandIntegrity(NULL, false) != 0) {
        Debug("Basic NAND integrity check failed!");
        Debug("You can not continue here");
        return 1;
    }
    
    // validate FIRM for 2.1
    DecryptNandToHash(l_sha256, firm0_info->offset, firm21_size, firm0_info);
    if (memcmp(l_sha256, firm21_sha256, 32) != 0) {
        Debug("FIRM0 hash mismatch!");
        return 1;
    }
    
    // find out 3DS region
    u8* secureInfo = BUFFER_ADDRESS;
    if (SeekFileInNand(&offset, &size, "RW         SYS        SECURE~?   ", ctrnand_info) != 0) {
        Debug("SecureInfo_A not found!");
        return 1;
    }
    if (DecryptNandToMem(secureInfo, offset, size, ctrnand_info) != 0)
        return 1;
    if (secureInfo[0x100] == 0) {
        Debug("Your region is: JAP");
        checklist = (TitleHashInfo*) JAP_sha256;
        n_titles = JAP_sha256_size / sizeof(TitleHashInfo);
    } else if (secureInfo[0x100] == 1) {
        Debug("Your region is: USA");
        checklist = (TitleHashInfo*) USA_sha256;
        n_titles = USA_sha256_size / sizeof(TitleHashInfo);
    } else if (secureInfo[0x100] == 2) {
        Debug("Your region is: EUR");
        checklist = (TitleHashInfo*) EUR_sha256;
        n_titles = EUR_sha256_size / sizeof(TitleHashInfo);
    } else {
        Debug("Unsupported region");
        return 1;
    }
    
    for (u32 t = 0; t < n_titles; t++) {
        u32 offset_app[max_num_apps]; // 8 should be more than enough
        u32 size_app[max_num_apps];
        u32 title_state;
        
        Debug("Checking title %08X%08X...", (unsigned int) (checklist[t].titleId >> 32), (unsigned int) (checklist[t].titleId & 0xFFFFFFFF));
        ShowProgress(t, n_titles);
        
        if (((checklist[t].titleId >> 44) & 0xFF) == 0x48) {
            Debug("Is a TWL title, skipped");
            n_skipped++;
            continue;
        }   
        
        title_state = SeekTitleInNand(&offset, &size, offset_app, size_app, checklist[t].titleId, max_num_apps);
        if ((title_state == S_TMD_NOT_FOUND) || (title_state == S_TMD_IS_CORRUPT)) {
            Debug("TMD not found or corrupt");
            n_not_found++;
            continue;
        }
        DecryptNandToHash(l_sha256, offset, size, ctrnand_info);
        if (memcmp(l_sha256, checklist[t].sha256, 32) != 0) {
            Debug("TMD hash mismatch");
            n_not_matched++;
            continue;
        }
        n_tmd_success++;
        
        // TMD verified succesfully, now verifying apps
        if (title_state != S_APP_NOT_FOUND) {
            u8* tmd_data = (u8*) 0x20316000;
            if (DecryptNandToMem(tmd_data, offset, size, ctrnand_info) != 0)
                return 1; 
            tmd_data += (tmd_data[3] == 3) ? 0x240 : (tmd_data[3] == 4) ? 0x140 : 0x80;
            u8* content_list = tmd_data + 0xC4 + (64 * 0x24);
            u32 cnt_count = getbe16(tmd_data + 0x9E);
            u32 n_verified = max_num_apps;
            for (u32 i = 0; i < max_num_apps && i < cnt_count; i++) {
                u8* app_sha256 = content_list + (0x30 * i) + 0x10;
                DecryptNandToHash(l_sha256, offset_app[i], size_app[i], ctrnand_info);
                if (memcmp(l_sha256, app_sha256, 32) != 0) {
                    n_verified = i;
                    break;
                }
            }
            if ((n_verified < max_num_apps) && (n_verified < cnt_count)) {
                Debug("APP hash mismatch");
                n_app_not_matched++;
                continue;
            }
        } else {
            Debug("APP not found");
            n_app_not_found++;
            continue;
        }
        
        // full success if arriving here
        n_full_success++;
    }
    ShowProgress(0, 0);
    
    bool valstage1 = (n_tmd_success + n_app_not_found == n_titles - n_skipped);
    bool valstage2 = (n_full_success == n_titles - n_skipped);
    
    Debug("");
    Debug("Validation Stage 1: %s", (valstage1) ? "SUCCESS" : "FAILED");
    Debug("Validation Stage 2: %s", (valstage2) ? "SUCCESS" : "FAILED");
    
    if (n_full_success < n_titles) {
        if (n_skipped)
            Debug(" # TWL titles        : %3u", n_skipped);
        if (n_tmd_success < n_titles) {
            Debug(" # TMD success       : %3u", n_tmd_success);
            Debug(" # TMD not found     : %3u", n_not_found);
            Debug(" # TMD hash mismatch : %3u", n_not_matched);
        }
        Debug(" # APP success       : %3u", n_full_success);
        Debug(" # APP fragmented    : %3u", n_app_not_found); // or not found, but fragmentation is much more likely
        Debug(" # APP hash mismatch : %3u", n_app_not_matched);
    }
    
    Debug("");
    
    if (!valstage1) {
        Debug("WARNING: Validation Stage 1 failed!");
        Debug("!DO NOT %s!", (param & N_EMUNAND) ? "RESTORE THIS TO SYSNAND" : "REBOOT YOUR 3DS NOW");
        Debug("Starting from scratch is recommended");
        Debug("");
    } else if (!valstage2) {
        Debug("WARNING: Validation Stage 2 failed!");
        Debug("Everything might be fine, but we can't verify");
        Debug("It is recommended you defragment your CTRNAND");
        Debug("and run the Downgrade Validator again");
        Debug("");
    }
    
    return (valstage2) ? 0 : (valstage1) ? 2 : 1;
}
