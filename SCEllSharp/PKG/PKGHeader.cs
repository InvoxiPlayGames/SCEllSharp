using System.Text;

namespace SCEllSharp.PKG
{
    public class PKGHeader
    {
        public uint PackageMagic;
        public ushort PackageRevision;
        public ushort PackageType;
        public uint MetadataOffset;
        public uint MetadataCount;
        public uint MetadataSize;
        public uint NumberOfItems;
        public ulong TotalPackageSize;
        public ulong DataOffset;
        public ulong DataSize;
        public string? ContentID;
        public byte[]? DebugDigest;
        public byte[]? PackageIV;

        public void ReadHeader(Stream stream)
        {
            PackageMagic = stream.ReadUInt32BE();
            PackageRevision = stream.ReadUInt16BE();
            PackageType = stream.ReadUInt16BE();
            MetadataOffset = stream.ReadUInt32BE();
            MetadataCount = stream.ReadUInt32BE();
            MetadataSize = stream.ReadUInt32BE();
            NumberOfItems = stream.ReadUInt32BE();
            TotalPackageSize = stream.ReadUInt64BE();
            DataOffset = stream.ReadUInt64BE();
            DataSize = stream.ReadUInt64BE();
            byte[] ContentIDBytes = stream.ReadBytes(0x30);
            ContentID = Encoding.UTF8.GetString(ContentIDBytes);
            DebugDigest = stream.ReadBytes(0x10);
            PackageIV = stream.ReadBytes(0x10);
        }

        public void WriteHeader(Stream stream)
        {
            stream.WriteUInt32BE(PackageMagic);
            stream.WriteUInt16BE(PackageRevision);
            stream.WriteUInt16BE(PackageType);
            stream.WriteUInt32BE(MetadataOffset);
            stream.WriteUInt32BE(MetadataCount);
            stream.WriteUInt32BE(MetadataSize);
            stream.WriteUInt32BE(NumberOfItems);
            stream.WriteUInt64BE(TotalPackageSize);
            stream.WriteUInt64BE(DataOffset);
            stream.WriteUInt64BE(DataSize);
            // pad out content ID to 0x30 bytes
            byte[] ContentIDBytes = new byte[0x30];
            byte[] ContentIDASCII = Encoding.UTF8.GetBytes(ContentID!);
            Array.Copy(ContentIDASCII, ContentIDBytes, ContentIDASCII.Length);
            stream.Write(ContentIDBytes, 0, 0x30);
            stream.Write(DebugDigest!, 0, 0x10);
            stream.Write(PackageIV!, 0, 0x10);
        }
    }
}
