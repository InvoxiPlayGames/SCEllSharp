using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
    }
}
