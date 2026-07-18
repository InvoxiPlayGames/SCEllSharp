using System.Text;

namespace SCEllSharp.PKG
{
    public class PKGExtendedHeader
    {
        public uint PkgExtMagic;
        public uint PkgExtRevision;
        public uint ExtendedHeaderSize;
        public uint ExtendedDataSize;
        public uint HeaderSigOffset;
        public uint MetadataSigOffset;
        public ulong TailOffset;
        public uint Unused;
        public uint KeyID;
        public uint FullHeaderSigOffset;
        public byte[]? Padding;

        public void ReadExtHeader(Stream stream)
        {
            PkgExtMagic = stream.ReadUInt32BE();
            PkgExtRevision = stream.ReadUInt32BE();
            ExtendedHeaderSize = stream.ReadUInt32BE();
            ExtendedDataSize = stream.ReadUInt32BE();
            HeaderSigOffset = stream.ReadUInt32BE();
            MetadataSigOffset = stream.ReadUInt32BE();
            TailOffset = stream.ReadUInt64BE();
            Unused = stream.ReadUInt32BE();
            KeyID = stream.ReadUInt32BE();
            FullHeaderSigOffset = stream.ReadUInt32BE();
            Padding = stream.ReadBytes(0x14);
        }

        public void WriteExtHeader(Stream stream)
        {
            stream.WriteUInt32BE(PkgExtMagic);
            stream.WriteUInt32BE(PkgExtRevision);
            stream.WriteUInt32BE(ExtendedHeaderSize);
            stream.WriteUInt32BE(ExtendedDataSize);
            stream.WriteUInt32BE(HeaderSigOffset);
            stream.WriteUInt32BE(MetadataSigOffset);
            stream.WriteUInt64BE(TailOffset);
            stream.WriteUInt32BE(Unused);
            stream.WriteUInt32BE(KeyID);
            stream.WriteUInt32BE(FullHeaderSigOffset);
            stream.Write(Padding!, 0, 0x14);
        }
    }
}
