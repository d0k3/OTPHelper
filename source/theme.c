#include "theme.h"
#ifdef USE_THEME
#include "fs.h"
#include "decryptor/nand.h"

bool ImportFrameBuffer(const char* path, u32 use_top) {
    u32 bufsize = BYTES_PER_PIXEL * SCREEN_HEIGHT * ((use_top) ? SCREEN_WIDTH_TOP : SCREEN_WIDTH_BOT);
    u8* buffer0 = (use_top) ? TOP_SCREEN0 : BOT_SCREEN0;
    u8* buffer1 = (use_top) ? TOP_SCREEN1 : BOT_SCREEN1;
    bool result;
    
    if (!FileOpen(path)) return false;
    result = FileRead(buffer0, bufsize, 0);
    memcpy(buffer1, buffer0, bufsize);
    FileClose();
    
    return result;
}

void LoadThemeGfx(const char* filename, bool use_top) {
    char path[256];
    #ifdef APP_TITLE
    snprintf(path, 256, "//3ds/%s/UI/%s", APP_TITLE, filename);
    if (ImportFrameBuffer(path, use_top)) return;
    #endif
    snprintf(path, 256, "//%s/%s", USE_THEME, filename);
    if (!ImportFrameBuffer(path, use_top))
        DrawStringF(10, 230, true, "Not found: %s", filename);
}

void LoadThemeGfxMenu(u32 index) {
    char filename[16];
    snprintf(filename, 16, "menu%04lu.bin", index);
    LoadThemeGfx(filename, !LOGO_TOP); // this goes where the logo goes not
}

void LoadThemeGfxLogo(void) {
    LoadThemeGfx(GFX_LOGO, LOGO_TOP);
    #if defined LOGO_TEXT_X && defined LOGO_TEXT_Y
    u32 emunand_state = CheckEmuNand();
    DrawStringF(LOGO_TEXT_X, LOGO_TEXT_Y -  0, LOGO_TOP, "SD card: %lluMB/%lluMB & %s", RemainingStorageSpace() / 1024 / 1024, TotalStorageSpace() / 1024 / 1024, (emunand_state == EMUNAND_READY) ? "EmuNAND ready" : (emunand_state == EMUNAND_GATEWAY) ? "GW EmuNAND" : (emunand_state == EMUNAND_REDNAND) ? "RedNAND" : (emunand_state > 3) ? "MultiNAND" : "no EmuNAND");
    DrawStringF(LOGO_TEXT_X, LOGO_TEXT_Y - 10, LOGO_TOP, "Game directory: %s", GAME_DIR);
    #ifdef WORK_DIR
    if (DirOpen(WORK_DIR)) {
        DrawStringF(LOGO_TEXT_X, LOGO_TEXT_Y - 20, LOGO_TOP, "Work directory: %s", WORK_DIR);
        DirClose();
    }
    #endif
    #endif
}

#ifdef ALT_PROGRESS
void ShowProgress(u64 current, u64 total) {
    const u32 nSymbols = PRG_BARWIDTH / 8;
    char progStr[nSymbols + 1];
    
    memset(progStr, (int) ' ', nSymbols);
    if (total > 0) {
        for (u32 s = 0; s < ((nSymbols * current) / total); s++)
            progStr[s] = '\xDB';
    }
    progStr[nSymbols] = '\0';
    
    DrawString(BOT_SCREEN0, progStr, PRG_START_X, PRG_START_Y, PRG_COLOR_FONT, PRG_COLOR_BG);
    DrawString(BOT_SCREEN1, progStr, PRG_START_X, PRG_START_Y, PRG_COLOR_FONT, PRG_COLOR_BG);
}
#endif
#endif
