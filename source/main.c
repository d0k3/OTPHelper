#include "common.h"
#include "draw.h"
#include "fs.h"
#include "menu.h"
#include "i2c.h"
#include "decryptor/nand.h"
#include "decryptor/otphelper.h"

#define SUBMENU_START 1


MenuInfo menu[] =
{
    {
        #ifdef EXEC_OLDSPIDER
        #ifndef VERSION_NAME
        "OTPHelper FW 2.1 Main Menu", 9,
        #else
        VERSION_NAME, 9,
        #endif
        {
            { "Dump otp.bin (0x100)",         DumpOtp,                0 },
            { "Dump otp.bin (0x108)",         DumpOtp,                OTP_BIG },
            { "Validate otp.bin (0x100)",     CheckOtp,               0 },
            { "Validate otp.bin (0x108)",     CheckOtp,               OTP_BIG },
            { "NAND Validation Options...",   NULL,                   SUBMENU_START + 0 },
            { "NAND Backup & Restore...",     NULL,                   SUBMENU_START + 1 },
            { "CTRNAND Dump & Inject...",     NULL,                   SUBMENU_START + 2 },
            { "FIRM Dump & Inject...",        NULL,                   SUBMENU_START + 3 },
            { "NAND XORpads...",              NULL,                   SUBMENU_START + 4 }
        }
        #else
        #ifndef VERSION_NAME
        "OTPHelper N3DS Main Menu", 8,
        #else
        VERSION_NAME, 8,
        #endif
        {
            { "One Click Setup",              OneClickSetup,          N_NANDWRITE },
            { "Unbrick FW 2.1 EmuNAND",       UnbrickNand,            HDR_FROM_MEM | N_EMUNAND | N_NANDWRITE },
            { "otp.bin -> otp0x108.bin",      ExpandOtp,              0 },
            { "NAND Validation Options...",   NULL,                   SUBMENU_START + 0 },
            { "NAND Backup & Restore...",     NULL,                   SUBMENU_START + 1 },
            { "CTRNAND Dump & Inject...",     NULL,                   SUBMENU_START + 2 },
            { "FIRM Dump & Inject...",        NULL,                   SUBMENU_START + 3 },
            { "NAND XORpads...",              NULL,                   SUBMENU_START + 4 }
        }
        #endif
    },
    {
        "NAND Validation", 5,
        {
            { "Validate NAND Backup",         &ValidateNand,          N_NANDFILE },
            { "Validate SysNAND",             &ValidateNand,          0 },
            { "Validate EmuNAND",             &ValidateNand,          N_EMUNAND },
            { "Validate SysNAND Downgrade",   &ValidateDowngrade,     0 },
            { "Validate EmuNAND Downgrade",   &ValidateDowngrade,     N_EMUNAND }
        }
    },
    {
        "NAND Backup & Restore", 5,
        {            
            { "SysNAND Backup",               &DumpNand,              0 },
            { "SysNAND Restore",              &RestoreNand,           N_NANDWRITE },
            { "EmuNAND Backup",               &DumpNand,              N_EMUNAND },
            { "EmuNAND Restore",              &RestoreNand,           N_EMUNAND | N_FORCENAND | N_NANDWRITE },
            { "Clone EmuNAND to SysNAND",     &RestoreNand,           N_DIRECT | N_NANDWRITE }
        }
    },
    {
        "CTRNAND Dump & Inject", 4,
        {            
            { "SysNAND CTRNAND Dump",         &DecryptNandPartition,  P_CTRNAND },
            { "SysNAND CTRNAND Inject",       &InjectNandPartition,   N_NANDWRITE | P_CTRNAND },
            { "EmuNAND CTRNAND Dump",         &DecryptNandPartition,  N_EMUNAND | P_CTRNAND },
            { "EmuNAND CTRNAND Inject",       &InjectNandPartition,   N_NANDWRITE | N_EMUNAND | P_CTRNAND }
        }
    },
    {
        "FIRM Dump & Inject", 8,
        {            
            { "SysNAND FIRM0 Dump",           &DecryptNandPartition,  P_FIRM0 },
            { "SysNAND FIRM0 Inject",         &InjectNandPartition,   N_NANDWRITE | N_SMALLER | P_FIRM0 },
            { "EmuNAND FIRM0 Dump",           &DecryptNandPartition,  N_EMUNAND | P_FIRM0 },
            { "EmuNAND FIRM0 Inject",         &InjectNandPartition,   N_NANDWRITE | N_SMALLER | N_EMUNAND | P_FIRM0 },
            { "SysNAND FIRM1 Dump",           &DecryptNandPartition,  P_FIRM1 },
            { "SysNAND FIRM1 Inject",         &InjectNandPartition,   N_NANDWRITE | N_SMALLER | P_FIRM1 },
            { "EmuNAND FIRM1 Dump",           &DecryptNandPartition,  N_EMUNAND | P_FIRM1 },
            { "EmuNAND FIRM1 Inject",         &InjectNandPartition,   N_NANDWRITE | N_SMALLER | N_EMUNAND | P_FIRM1 }
        }
    },
    {
        "NAND XORpads", 4,
        {
            { "CTRNAND Padgen",               &CtrNandPadgen,         0 },
            { "CTRNAND Padgen (slot 0x4)",    &CtrNandPadgen,         PG_FORCESLOT4 },
            { "TWLNAND Padgen",               &TwlNandPadgen,         0 },
            { "FIRM0FIRM1 Padgen",            &Firm0Firm1Padgen,      0 }
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

    u32 menu_exit = ProcessMenu(menu, SUBMENU_START);
    
    DeinitFS();
    (menu_exit == MENU_EXIT_REBOOT) ? Reboot() : PowerOff();
    return 0;
}
