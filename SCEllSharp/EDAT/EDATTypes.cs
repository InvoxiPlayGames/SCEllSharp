namespace SCEllSharp.EDAT
{
    [Flags]
    public enum EDATFlags : uint
    {
        Compressed = 0x1,
        Unknown_0x2 = 0x2,
        Unknown_0x4 = 0x4,
        EncryptedKey = 0x8,
        Unknown_0x10 = 0x10,
        Unknown_0x20 = 0x20,
        SDAT = 0x01000000,
        Debug = 0x80000000,
    }
}
