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
};
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
    
    Debug("Switching CTRNAND partition 0x%u -> 0x%u...", (to_o3ds) ? 5 : 4, (to_o3ds) ? 4 : 5);
    u32 size = partition_from->size;
    u32 offset = partition_from->offset;
    u32 result = 0;
    for (u32 i = 0; i < size; i += NAND_SECTOR_SIZE * SECTORS_PER_READ) {
        u32 read_bytes = min(NAND_SECTOR_SIZE * SECTORS_PER_READ, (size - i));
        ShowProgress(i, size);
        if (DecryptNandToMem(buffer, offset + i, read_bytes, partition_from) != 0) {
            Debug("NAND read failure");
            result = 1;
            break;
        }
        if (EncryptMemToNand(buffer, offset + i, read_bytes, partition_to) != 0) {
            Debug("NAND write failure");
            result = 1;
            break;
        }
    }
    ShowProgress(0, 0);
    
    return result;
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

u32 DumpEmergencyFiles(u32 param)
{
    static const char* dump_name[] = {
        "emergency_SecureInfo_A", "emergency_movable.sed", "emergency_LocalFriendCodeSeed_B",
        "emergency_title.db", "emergency_ticket.db"
    };
    static const char* dump_path[] = {
        "RW         SYS        SECURE~?   ", "PRIVATE    MOVABLE SED", "RW         SYS        LOCALF~?   ",
        "DBS        TITLE   DB ", "DBS        TICKET  DB "
    };
    static const u32 n_dump_files = sizeof(dump_name) / sizeof(char*);
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    u32 result = 0;
    
    Debug("Dumping emergency files...");
    
    // NAND header
    #ifdef EXEC_OLDSPIDER
    if (GetUnitPlatform() == PLATFORM_N3DS) {
        Debug("N3DS Header can't be dumped on 2.1");
        Debug("Failed!");
        result = 1;
    } else {
        result |= DumpNandHeader(param);
        Debug((result == 0) ? "Done!" : "Failed!");
    }
    #else
    result |= DumpNandHeader(param);
    Debug((result == 0) ? "Done!" : "Failed!");
    #endif
    
    // FIRM0FIRM1 XORpad
    if (Firm0Firm1Padgen(0) == 0) {
        Debug("Done!");
    } else {
        Debug("Failed!");
        result = 1;
    }
    
    // other dump files
    for (u32 i = 0; i < n_dump_files; i++) {
        u32 offset;
        u32 size;
        if ((SeekFileInNand(&offset, &size, dump_path[i], ctrnand_info, NULL) != 0) ||
            (DecryptNandToFile(dump_name[i], offset, size, ctrnand_info) != 0)) {
            Debug("Failed!");
            result = 1;
        } else {
            Debug ("Done!");
        }
    }
    
    return result;
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
    // see: https://www.3dbrew.org/wiki/Flash_Filesystem
    const u32 ctrnand_o3ds_border = 0x0B95CA00 + 0x2F3E3600; 
    const u32 max_num_apps = 8;
    
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    PartitionInfo* firm0_info = GetPartitionInfo(P_FIRM0);
    
    TitleHashInfo* checklist = NULL;
    bool valstage0 = true;
    u32 n_titles = 0;
    
    u32 n_full_success = 0;
    u32 n_tmd_success = 0;
    u32 n_skipped = 0;
    u32 n_not_found = 0;
    u32 n_app_not_found = 0;
    u32 n_app_fragmented = 0;
    u32 n_beyound_border = 0;
    
    u8  l_sha256[32];
    u32 offset;
    u32 size;
    
    
    // check if unbricked
    if (!(param & DG_FORCECHECK) && (CheckNandHeader(NULL) == NAND_HDR_N3DS)) {
        Debug("NAND is not downgraded or still bricked");
        return 1;
    }
    
    // perform basic NAND validation
    if (CheckNandIntegrity(NULL) != 0) {
        Debug("Basic NAND integrity check failed!");
        valstage0 = false;
    }
    
    // validate FIRM for 2.1
    DecryptNandToHash(l_sha256, firm0_info->offset, firm21_size, firm0_info);
    if (memcmp(l_sha256, firm21_sha256, 32) != 0) {
        Debug("FIRM0 hash mismatch!");
        valstage0 = false;
    }
    
    // find out 3DS region
    u8* secureInfo = BUFFER_ADDRESS;
    if (SeekFileInNand(&offset, &size, "RW         SYS        SECURE~?   ", ctrnand_info, NULL) != 0) {
        Debug("SecureInfo_A not found!");
        valstage0 = false;
    } else {
        if (DecryptNandToMem(secureInfo, offset, size, ctrnand_info) != 0)
            valstage0 = false;
        // check SecureInfo_A for corruption
        if ((secureInfo[0x101] == '\0') && (secureInfo[0x110] == '\0')) {
            char* sn = (char*) secureInfo + 0x102;
            Debug("Your serial number is: %s", sn);
            // check serial number
            u32 sn_chk = 0;
            for (; (sn_chk < 0xF) && (sn[sn_chk] >= 'A') && (sn[sn_chk] <= 'Z'); sn_chk++);
            if ((sn_chk < 2) || (sn_chk > 4)) { // less than 2, more than 4 uppercase letters
                Debug("Bad serial number!");
                valstage0 = false;
            }
            for (; (sn_chk < 0xF) && (sn[sn_chk] >= '0') && (sn[sn_chk] <= '9'); sn_chk++);
            if ((sn_chk >= 0xF) || (sn[sn_chk] != '\0')) { // numerical part fail?
                Debug("Bad serial number!");
                valstage0 = false;
            }
        } else {
            Debug("SecureInfo_A may be corrupted!");
            valstage0 = false;
        }
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
    }
    
    for (u32 t = 0; (t < n_titles) && valstage0; t++) {
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
        
        title_state = SeekTitleInNand(&offset, &size, offset_app, size_app, checklist[t].titleId, checklist[t].sha256, max_num_apps);
        if ((title_state == S_TMD_NOT_FOUND) || (title_state == S_TMD_IS_CORRUPT)) {
            Debug("TMD not found or corrupt");
            n_not_found++;
            continue;
        }
        n_tmd_success++;
        if (offset + size > ctrnand_o3ds_border) {
            Debug("TMD is in unmapped area");
            n_beyound_border++;
            continue;
        }
        
        // TMD verified succesfully, now verifying apps
        if (title_state == S_APP_NOT_FOUND) {
            Debug("APP not found or corrupt");
            n_app_not_found++;
            continue;
        } else if (title_state == S_APP_FRAGMENTED) {
            Debug("APP is fragmented");
            n_app_fragmented++;
            continue;
        } else {
            u32 n_chk = 0;
            for (; n_chk < max_num_apps; n_chk++) {
                if (!size_app[n_chk]) {
                    break;
                } else if (offset_app[n_chk] + size_app[n_chk] > ctrnand_o3ds_border) {
                    Debug("APP(%i) is in unmapped area", n_chk);
                    break;
                }
            }
            if ((n_chk < max_num_apps) && size_app[n_chk]) {
                n_beyound_border++;
                continue;
            }
        }
        
        // full success if arriving here
        n_full_success++;
    }
    ShowProgress(0, 0);
    
    bool valstage1 = (n_tmd_success - n_app_not_found - n_beyound_border == n_titles - n_skipped) && valstage0;
    bool valstage2 = (n_full_success == n_titles - n_skipped) && valstage0;
    
    Debug("");
    Debug("Validation Stage 0: %s", (valstage0) ? "SUCCESS" : "FAILED");
    Debug("Validation Stage 1: %s", (valstage1) ? "SUCCESS" : "FAILED");
    Debug("Validation Stage 2: %s", (valstage2) ? "SUCCESS" : "FAILED");
    
    if ((n_full_success < n_titles) && valstage0) {
        if (n_skipped)
            Debug(" # TWL titles        : %3u", n_skipped);
        if (n_beyound_border)
            Debug(" # In unmapped area  : %3u", n_beyound_border);
        if (n_tmd_success < n_titles) {
            Debug(" # TMD success       : %3u", n_tmd_success);
            Debug(" # TMD not found     : %3u", n_not_found);
        }
        Debug(" # APP success       : %3u", n_full_success);
        Debug(" # APP not found     : %3u", n_app_not_found); 
        Debug(" # APP fragmented    : %3u", n_app_fragmented);
    }
    
    Debug("");
    
    if (!valstage0 || !valstage1) {
        Debug("WARNING: Validation Stage %i failed!", (valstage0) ? 1 : 0);
        if (param & N_EMUNAND) {
            Debug("!DO NOT RESTORE THIS TO SYSNAND!");
            Debug("Starting from scratch is recommended");
        } else {
            Debug("!DO NOT REBOOT YOUR 3DS NOW!");
            Debug("You need to fix your SysNAND first");
        }
        Debug("");
    } else if (!valstage2) {
        Debug("WARNING: Validation Stage 2 failed!");
        Debug("Everything might be fine, but we can't verify");
        Debug("It is recommended you defragment your CTRNAND");
        Debug("and run the Downgrade Validator again");
        Debug("");
    }
    
    return (valstage2) ? 0 : (valstage1 && valstage0) ? 2 : 1;
}

u32 OneClickSetup(u32 param)
{
    if (!(param & N_NANDWRITE) || (param & N_EMUNAND)) // developer screwup protection
        return 1;
        
    if (SetNand(true, false) != 0) // set NAND to emuNAND
        return 1;
        
    // unbrick EmuNAND only if required
    if ((GetUnitPlatform() == PLATFORM_N3DS) && (CheckNandHeader(NULL) == NAND_HDR_N3DS)) {
        if (ValidateDowngrade(param | N_EMUNAND | DG_FORCECHECK) == 1) {
            Debug("Did you forget about downgrading first?");
            return 1;
        }
        Debug("EmuNAND is not yet unbricked, unbricking it now");
        if (UnbrickNand(param | N_EMUNAND | HDR_FROM_MEM) != 0) // unbrick emuNAND
            return 1;
    }
    
    Debug("");
    
    // check Downgrade integrity
    u32 dg_state = ValidateDowngrade(param | N_EMUNAND);
    if (dg_state == 2) {
        Debug("Downgrade Validation failed at Stage 2");
        Debug("It is recommended you defragment your CTRNAND");
        Debug("and run this again.");
        Debug("");
        Debug("Press <A> to continue anyways, <B> to stop");
        while (true) {
            u32 pad_state = InputWait();
            if (pad_state & BUTTON_A) {
                break;
            } else if (pad_state & BUTTON_B) {
                Debug("Cancelled by user");
                return 1;
            }
        }
    } else if (dg_state != 0) {
        Debug("Downgrade Validation failed!");
        Debug("You cannot continue here");
        return 1;
    }
    
    Debug("");
    
    if (SetNand(false, false) != 0) // set NAND back to sysNAND
        return 1;
        
    // check for SysNAND backup
    if (FileOpen("sysNAND_original.bin") || FileOpen("sysNAND.bin")) {
        FileClose(); // found backup, everything should be fine
    } else {
        Debug("Did you forget the SysNAND backup?");
        Debug("THIS IS YOUR LAST CHANCE TO BACKUP!");
        Debug("");
        Debug("Press <A> to backup to sysNAND_auto.bin");
        Debug("Press <B> to skip (not recommended)");
        while (true) {
            u32 pad_state = InputWait();
            if (pad_state & BUTTON_A) {
                if (DumpNand(N_NOASK) != 0)
                    return 1;
                break;
            } else if (pad_state & BUTTON_B) {
                break;
            }
        }
        Debug("");
    }
    
    // dump emergency files - this is unchecked
    DumpEmergencyFiles(0);
        
    if (RestoreNand(param | N_DIRECT) != 0) {
        Debug("NAND clone to SysNAND failed!");
        Debug("You cannot continue here and you");
        Debug("may need to restore your SysNAND");
        return 1;
    }
    
    Debug("");
    
    if (ValidateDowngrade(param) == 1) { // might be redundant
        Debug("SysNAND downgrade check failed!");
        Debug("You need to restore your SysNAND from");
        Debug("a valid backup.");
        return 1;
    }
    
    return 0;
}
