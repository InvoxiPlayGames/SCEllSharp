namespace SCEllSharp.PKG
{
    // unsure on these, total guesses from ps3devwiki / RPCS3 / RB3 PKGs
    [Flags]
    internal enum PKGFileFlags : uint
    {
        None = 0,
        NPDRM = 0x1, // set on all files?
        EDAT = 0x2,
        Directory = 0x4,
        SELF = 0x100,
        PSPCrypto = 0x10000000,
        Overwrites = 0x80000000
    }

    internal class PKGFileEntry
    {
        public uint FilenameOffset;
        public uint FilenameSize;
        public ulong DataOffset;
        public ulong DataSize;
        public PKGFileFlags Flags;
        public uint Unknown;

        public void ReadEntry(Stream stream)
        {
            FilenameOffset = stream.ReadUInt32BE();
            FilenameSize = stream.ReadUInt32BE();
            DataOffset = stream.ReadUInt64BE();
            DataSize = stream.ReadUInt64BE();
            Flags = (PKGFileFlags)stream.ReadUInt32BE();
            Unknown = stream.ReadUInt32BE();
        }

        public void WriteEntry(Stream stream)
        {
            stream.WriteUInt32BE(FilenameOffset);
            stream.WriteUInt32BE(FilenameSize);
            stream.WriteUInt64BE(DataOffset);
            stream.WriteUInt64BE(DataSize);
            stream.WriteUInt32BE((uint)Flags);
            stream.WriteUInt32BE(Unknown);
        }
    }
}
