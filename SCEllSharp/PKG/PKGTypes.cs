using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SCEllSharp.PKG
{
    internal enum PKGMetadataType
    {
        None = 0x0,
        DRMType = 0x1,
        ContentType = 0x2,
        PackageType = 0x3,
        PackageSize = 0x4,
        PackageVersion = 0x5,
        QADigest = 0x7,
        SystemAndAppVersion = 0x8,
        UnknownAllZeroes = 0x9,
        InstallDirectory = 0xA,
    }

    // unsure on these, taken from ps3devwiki
    public enum PKGContentType : uint
    {
        Unknown = 0x0,
        GameData = 0x4,
        GameExec = 0x5,
        PS1emu = 0x6,
        PSP = 0x7,
        Theme = 0x9,
        Widget = 0xA,
        License = 0xB,
        VSHModule = 0xC,
        PSNAvatar = 0xD,
        PSPgo = 0xE,
        minis = 0xF,
        PS2Classic = 0x12
    }

    // unsure on these, total guesses from ps3devwiki / RPCS3 / RB3 PKGs
    [Flags]
    public enum PKGFileFlags : uint
    {
        None = 0,
        NPDRM = 0x1, // set on all files?
        EDAT = 0x2,
        Directory = 0x4,
        SELF = 0x100,
        PSPCrypto = 0x10000000,
        Overwrites = 0x80000000
    }

    // unsure on these, taken from ps3devwiki, very wrong!!!
    [Flags]
    public enum PKGFlags : uint
    {
        None = 0x0,
        Unknown_0x1 = 0x1,
        EBOOT = 0x2,
        RequireLicense = 0x4,
        Unknown_0x8 = 0x8,
        CumulativePatch = 0x10,
        Unknown_0x20 = 0x20,
        RenameDirectory = 0x40,
        EDAT = 0x80,
        Unknown_0x100 = 0x100,
        Emulator = 0x200,
        VSHModule = 0x400,
        DiscBinded = 0x800
    }
}
