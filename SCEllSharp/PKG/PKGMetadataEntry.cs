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

    internal class PKGMetadataEntry
    {
        public PKGMetadataType Type;
        public uint Length;
        public byte[]? Data;

        public void ReadEntry(Stream stream)
        {
            Type = (PKGMetadataType)stream.ReadUInt32BE();
            Length = stream.ReadUInt32BE();
            Data = stream.ReadBytes((int)Length);
        }

        public void WriteEntry(Stream stream)
        {
            stream.WriteUInt32BE((uint)Type);
            stream.WriteUInt32BE(Length);
            if (Length > 0)
                stream.Write(Data!, 0, (int)Length);
        }

        public void SetData(byte[] data)
        {
            Length = (uint)data.Length;
            Data = data;
        }
    }
}
