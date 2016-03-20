#include "fs.h"
#include "draw.h"
#include "platform.h"
#include "decryptor/sha.h"
#include "decryptor/decryptor.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"


u32 SeekFileInNand(u32* offset, u32* size, const char* path, PartitionInfo* partition, u8* sha256)
{
    // poor mans NAND FAT file seeker:
    // - path must be in FAT 8+3 format, without dots or slashes
    //   example: DIR1_______DIR2_______FILENAMEEXT
    // - can't handle long filenames
    // - dirs must not exceed 1024 entries
    // - fragmentation not supported
    
    u8* buffer = BUFFER_ADDRESS;
    u32 p_size = partition->size;
    u32 p_offset = partition->offset;
    u32 fat_pos = 0;
    bool found = false;
    
    if (strnlen(path, 256) % (8+3) != 0)
        return 1;
    
    DecryptNandToMem(buffer, p_offset, NAND_SECTOR_SIZE, partition);
    
    // good FAT header description found here: http://www.compuphase.com/mbr_fat.htm
    u32 fat_start = NAND_SECTOR_SIZE * getle16(buffer + 0x0E);
    u32 fat_count = buffer[0x10];
    u32 fat_size = NAND_SECTOR_SIZE * getle16(buffer + 0x16) * fat_count;
    u32 root_size = getle16(buffer + 0x11) * 0x20;
    u32 cluster_start = fat_start + fat_size + root_size;
    u32 cluster_size = buffer[0x0D] * NAND_SECTOR_SIZE;
    
    for (*offset = p_offset + fat_start + fat_size; strnlen(path, 256) >= 8+3; path += 8+3) {
        if (*offset - p_offset > p_size)
            return 1;
        found = false;
        DecryptNandToMem(buffer, *offset, cluster_size, partition);
        for (u32 i = 0x00; i < cluster_size; i += 0x20) {
            const static char zeroes[8+3] = { 0x00 };
            // skip invisible, deleted and lfn entries
            if ((buffer[i] == '.') || (buffer[i] == 0xE5) || (buffer[i+0x0B] == 0x0F))
                continue;
            else if (memcmp(buffer + i, zeroes, 8+3) == 0)
                return 1;
            u32 p; // search for path in fat folder structure, accept '?' wildcards
            for (p = 0; (p < 8+3) && (path[p] == '?' || buffer[i+p] == path[p]); p++);
            if (p != 8+3) continue;
            // candidate found, store offset and move on
            fat_pos = getle16(buffer + i + 0x1A);
            u32 tmp_offset = p_offset + cluster_start + (fat_pos - 2) * cluster_size;
            u32 tmp_size = getle32(buffer + i + 0x1C);
            // check hash
            if ((sha256 != NULL) && strnlen(path, 256) == 8+3) {
                u8 l_sha256[32];
                DecryptNandToHash(l_sha256, tmp_offset, tmp_size, partition);
                if (memcmp(sha256, l_sha256, 32) != 0)
                    continue;
            }
            // found!
            *offset = tmp_offset;
            *size = tmp_size;
            found = true;
            break;
        }
        if (!found) break;
    }
    
    // check for fragmentation
    if (found && (*size > cluster_size)) {  
        if (fat_size / fat_count > 0x100000) // prevent buffer overflow
            return 1; // fishy FAT table size - should never happen
        DecryptNandToMem(buffer, p_offset + fat_start, fat_size / fat_count, partition);
        for (u32 i = 0; i < (*size - 1) / cluster_size; i++) {
            if (*(((u16*) buffer) + fat_pos + i) != fat_pos + i + 1)
                return 2;
        } // no need to check the files last FAT table entry
    }
    
    return (found) ? 0 : 1;
}

u32 SeekTitleInNandDb(u32* tmd_id, u64 titleId)
{
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    u8* titledb = (u8*) 0x20316000;
    bool found = false;
    
    u32 offset_db;
    u32 size_db;
    if (SeekFileInNand(&offset_db, &size_db, "DBS        TITLE   DB ", ctrnand_info, NULL) != 0)
        return 1; // database not found
    if (size_db != 0x64C00)
        return 1; // bad database size
    if (DecryptNandToMem(titledb, offset_db, size_db, ctrnand_info) != 0)
        return 1;
    
    u8* entry_table = titledb + 0x39A80;
    u8* info_data = titledb + 0x44B80;
    if ((getle32(entry_table + 0) != 2) || (getle32(entry_table + 4) != 3))
        return 1; // magic number not found
    for (u32 i = 0; i < 1000; i++) {
        u8* entry = entry_table + 0xA8 + (0x2C * i);
        u8* info = info_data + (0x80 * i);
        if (getle64(entry + 0x8) != titleId) continue; // not a title id match
        if (getle32(entry + 0x4) != 1) continue; // not an active entry
        if ((getle32(entry + 0x18) - i != 0x162) || (getle32(entry + 0x1C) != 0x80) || (getle32(info + 0x08) != 0x40)) continue; // fishy title info / offset
        *tmd_id = getle32(info + 0x14);
        found = true;
        break; 
    }
    
    return (found) ? 0 : 1;
}

u32 SeekTitleInNand(u32* offset_tmd, u32* size_tmd, u32* offset_app, u32* size_app, u64 titleId, u8* tmd_sha256, u32 max_cnt)
{
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    u8* buffer = (u8*) 0x20316000;
    u32 cnt_count = 0;
    u32 tid_high = (titleId >> 32) & 0xFFFFFFFF;
    u32 tid_low = titleId & 0xFFFFFFFF;
    bool found_tmd = false;
    u32 tmd_id = 0;
    
    // Method 1: Search TMD in title.db
    if (SeekTitleInNandDb(&tmd_id, titleId) == 0) {
        char path[64];
        sprintf(path, "TITLE      %08X   %08X   CONTENT    %08XTMD", (unsigned int) tid_high, (unsigned int) tid_low, (unsigned int) tmd_id);
        if (SeekFileInNand(offset_tmd, size_tmd, path, ctrnand_info, tmd_sha256) == 0)
            found_tmd = true;
    }
    if (!found_tmd) { // Method 2: Search TMD in file system
        char path[64];
        sprintf(path, "TITLE      %08X   %08X   CONTENT    ????????TMD", (unsigned int) tid_high, (unsigned int) tid_low);
        if (SeekFileInNand(offset_tmd, size_tmd, path, ctrnand_info, tmd_sha256) == 0)
            found_tmd = true;
    }
    if (!found_tmd) // TMD not found
        return S_TMD_NOT_FOUND;
    if ((*size_tmd < 0xC4 + (0x40 * 0x24)) || (*size_tmd > 0x4000)) // TMD bad size
        return S_TMD_IS_CORRUPT;
        
    if (DecryptNandToMem(buffer, *offset_tmd, *size_tmd, ctrnand_info) != 0)
        return S_TMD_NOT_FOUND; // actually unknown error, but won't happen anyways, so what?
    u32 size_sig = (buffer[3] == 3) ? 0x240 : (buffer[3] == 4) ? 0x140 : (buffer[3] == 5) ? 0x80 : 0;         
    if ((size_sig == 0) || (memcmp(buffer, "\x00\x01\x00", 3) != 0)) // Unknown signature type
        return S_TMD_IS_CORRUPT;
    cnt_count = getbe16(buffer + size_sig + 0x9E);
    u32 size_tmd_expected = size_sig + 0xC4 + (0x40 * 0x24) + (cnt_count * 0x30);
    if (*size_tmd < size_tmd_expected) // TMD does not match expected size
        return S_TMD_IS_CORRUPT;
    buffer += size_sig + 0xC4 + (0x40 * 0x24); // this now points to the content list
    
    bool fragmented_apps = false;
    memset(offset_app, 0x00, max_cnt * sizeof(u32));
    memset(size_app, 0x00, max_cnt * sizeof(u32));
    for (u32 i = 0; i < cnt_count && i < max_cnt; i++) {
        char path[64];
        u32 cnt_id = getbe32(buffer + (0x30 * i));
        u8* app_sha256 = buffer + (0x30 * i) + 0x10;
        if (i >= max_cnt) continue; // skip app
        sprintf(path, "TITLE      %08X   %08X   CONTENT    %08XAPP", (unsigned int) tid_high, (unsigned int) tid_low, (unsigned int) cnt_id);
        u32 seek_state = SeekFileInNand(offset_app + i, size_app + i, path, ctrnand_info, app_sha256);
        if (seek_state == 2) fragmented_apps = true;
        else if (seek_state != 0) return S_APP_NOT_FOUND;
    }
    if (fragmented_apps) return S_APP_FRAGMENTED;
    
    return S_TITLE_FOUND;
}

/* u32 InjectHealthAndSafety(u32 param) // !!! reference only!
{
    u8* buffer = BUFFER_ADDRESS;
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    TitleListInfo* health = titleList + ((GetUnitPlatform() == PLATFORM_3DS) ? 3 : 4);
    NcchHeader* ncch = (NcchHeader*) 0x20316000;
    char filename[64];
    u32 offset_app[4];
    u32 size_app[4];
    u32 offset_tmd;
    u32 size_tmd;
    u32 size_hs;
    
    
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
    
    if (DebugSeekTitleInNand(&offset_tmd, &size_tmd, offset_app, size_app, health, 4) != 0)
        return 1;
    if (size_app[0] > 0x400000) {
        Debug("H&S system app is too big!");
        return 1;
    }
    if (DecryptNandToMem((void*) ncch, offset_app[0], 0x200, ctrnand_info) != 0)
        return 1;
    if (InputFileNameSelector(filename, NULL, "app", ncch->signature, 0x100, 0) != 0)
        return 1;
    
    if (!DebugFileOpen(filename))
        return 1;
    size_hs = FileGetSize();
    memset(buffer, 0, size_app[0]);
    if (size_hs > size_app[0]) {
        Debug("H&S inject app is too big!");
        return 1;
    }
    if (!DebugFileRead(buffer, size_hs, 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    if (!DebugFileCreate("hs.enc", true))
        return 1;
    if (!DebugFileWrite(buffer, size_app[0], 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    if (CryptNcch("hs.enc", 0, 0, 0, ncch->flags) != 0)
        return 1;
    
    Debug("Injecting H&S app...");
    if (EncryptFileToNand("hs.enc", offset_app[0], size_app[0], ctrnand_info) != 0)
        return 1;
    
    Debug("Fixing TMD...");
    u8* tmd_data = (u8*) 0x20316000;
    if (DecryptNandToMem(tmd_data, offset_tmd, size_tmd, ctrnand_info) != 0)
        return 1; 
    tmd_data += (tmd_data[3] == 3) ? 0x240 : (tmd_data[3] == 4) ? 0x140 : 0x80;
    u8* content_list = tmd_data + 0xC4 + (64 * 0x24);
    u32 cnt_count = getbe16(tmd_data + 0x9E);
    if (GetHashFromFile("hs.enc", 0, size_app[0], content_list + 0x10) != 0) {
        Debug("Failed!");
        return 1;
    }
    for (u32 i = 0, kc = 0; i < 64 && kc < cnt_count; i++) {
        u32 k = getbe16(tmd_data + 0xC4 + (i * 0x24) + 0x02);
        u8* chunk_hash = tmd_data + 0xC4 + (i * 0x24) + 0x04;
        sha_init(SHA256_MODE);
        sha_update(content_list + kc * 0x30, k * 0x30);
        sha_get(chunk_hash);
        kc += k;
    }
    u8* tmd_hash = tmd_data + 0xA4;
    sha_init(SHA256_MODE);
    sha_update(tmd_data + 0xC4, 64 * 0x24);
    sha_get(tmd_hash);
    tmd_data = (u8*) 0x20316000;
    if (EncryptMemToNand(tmd_data, offset_tmd, size_tmd, ctrnand_info) != 0)
        return 1; 
    
    
    return 0;
}*/
