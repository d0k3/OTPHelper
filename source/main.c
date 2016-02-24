#include "common.h"
#include "draw.h"
#include "fs.h"
#include "menu.h"
#include "i2c.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"
#include "decryptor/otphelper.h"

#define SUBMENU_START 1


MenuInfo menu_n3ds[] =
{
    {
        #ifndef BUILD_NAME
        "OTPHelper Main Menu", 8,
        #else
        BUILD_NAME, 8,
        #endif
        {
            { "Dump otp.bin (0x100) (< 3.0)", DumpOtp,                0 },
            { "Dump otp.bin (0x108) (< 3.0)", DumpOtp,                OTP_BIG },
            { "Switch EmuCTRNAND to Slot0x4", SwitchCtrNandCrypto,    N_EMUNAND | N_NANDWRITE | OTP_TO_O3DS },
            { "Switch EmuCTRNAND to Slot0x5", SwitchCtrNandCrypto,    N_EMUNAND | N_NANDWRITE | OTP_TO_N3DS },
            { "Backup EmuNAND header",        DumpNandHeader,         N_EMUNAND },
            { "Inject O3DS EmuNAND header",   InjectNandHeader,       N_EMUNAND | N_NANDWRITE | OTP_TO_O3DS },
            { "Inject N3DS EmuNAND header",   InjectNandHeader,       N_EMUNAND | N_NANDWRITE | OTP_TO_O3DS },
            { "MiniDecrypt9 (submenu)",       NULL,                   SUBMENU_START + 0 },
        }
    },
    {
        "MiniDecrypt9", 3,
        {            
            { "XORpad Submenu",               NULL,                   SUBMENU_START + 1 },
            { "SysNAND Submenu",              NULL,                   SUBMENU_START + 2 },
            { "EmuNAND Submenu",              NULL,                   SUBMENU_START + 3 }
        }
    },
    {
        "XORpad Options", 3,
        {            
            { "CTRNAND Padgen",               &CtrNandPadgen,         0 },
            { "CTRNAND Padgen (slot 0x4)",    &CtrNandPadgen,         PG_FORCESLOT4 },
            { "FIRM0FIRM1 Padgen",            &Firm0Firm1Padgen,      0 }
        }
    },
    {
        "SysNAND Options", 6,
        {
            { "SysNAND Backup",               &DumpNand,              0 },
            { "SysNAND Restore",              &RestoreNand,           N_NANDWRITE },
            { "Dump SysCTRNAND Partition",    &DecryptNandPartition,  P_CTRNAND },
            { "Inject SysCTRNAND Partition",  &InjectNandPartition,   N_NANDWRITE | P_CTRNAND },
            { "Health&Safety Dump",           &DumpHealthAndSafety,   0 },
            { "Health&Safety Inject",         &InjectHealthAndSafety, N_NANDWRITE }
        }
    },
    {
        "EmuNAND Options", 6,
        {
            { "EmuNAND Backup",               &DumpNand,              N_EMUNAND },
            { "EmuNAND Restore",              &RestoreNand,           N_EMUNAND | N_FORCENAND | N_NANDWRITE },
            { "Dump EmuCTRNAND Partition",    &DecryptNandPartition,  N_EMUNAND | P_CTRNAND },
            { "Inject EmuCTRNAND Partition",  &InjectNandPartition,   N_EMUNAND | N_NANDWRITE | P_CTRNAND },
            { "Health&Safety Dump",           &DumpHealthAndSafety,   N_EMUNAND },
            { "Health&Safety Inject",         &InjectHealthAndSafety, N_EMUNAND | N_NANDWRITE }
        }
    },
    {
        NULL, 0, {}, // empty menu to signal end
    }
};


void Reboot()
{
    i2cWriteRegister(I2C_DEV_MCU, 0x20, 1 << 2);
    while(true);
}


void PowerOff()
{
    i2cWriteRegister(I2C_DEV_MCU, 0x20, 1 << 0);
    while (true);
}


int main()
{
    ClearScreenFull(true, true);
    InitFS();

    u32 menu_exit = ProcessMenu(menu_n3ds, SUBMENU_START);
    
    DeinitFS();
    (menu_exit == MENU_EXIT_REBOOT) ? Reboot() : PowerOff();
    return 0;
}
