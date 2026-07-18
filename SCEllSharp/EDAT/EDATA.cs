using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SCEllSharp.NPDRM;

namespace SCEllSharp.EDAT
{
    public class EDATAHeader
    {
        public NPD? Npd;
        public EDATFlags Flags;
        public int BlockSize;
        public ulong DataSize;
        public byte[]? MetadataHash;
        public byte[]? EDATHeaderHash;
        public byte[]? MetadataSignature;
        public byte[]? HeaderSignature;

        public void Read(Stream stream)
        {
            Npd = new();
            Npd.Read(stream);
            Flags = (EDATFlags)stream.ReadUInt32BE();
            BlockSize = stream.ReadInt32BE();
            DataSize = stream.ReadUInt64BE();
            MetadataHash = stream.ReadBytes(0x10);
            EDATHeaderHash = stream.ReadBytes(0x10);
            MetadataSignature = stream.ReadBytes(0x28);
            HeaderSignature = stream.ReadBytes(0x28);
        }

        public void Write(Stream stream, bool partial = false)
        {
            Npd!.Write(stream);
            stream.WriteUInt32BE((uint)Flags);
            stream.WriteInt32BE(BlockSize);
            stream.WriteUInt64BE(DataSize);
            stream.Write(MetadataHash!, 0, 0x10);
            if (partial) return; // when calculating signatures the next few isn't needed
            stream.Write(EDATHeaderHash!, 0, 0x10);
            stream.Write(MetadataSignature!, 0, 0x28);
            stream.Write(HeaderSignature!, 0, 0x28);
        }
    }

    public class EDATA
    {
        private byte[]? _klicensee;
        private EDATAHeader? _header;
        private string? _footer;

        private byte[]? _ciphertext;

        public EDATA()
        {
            // TODO: generic constructor
        }

        public EDATA(Stream str, byte[]? klicensee = null)
        {
            _klicensee = klicensee;
            _header = new();
            _header.Read(str);
            if (_header.DataSize > 0)
            {
                int numHashes = ((int)_header.DataSize / (int)_header.BlockSize) + 1;
                _ciphertext = str.ReadBytes((int)_header.DataSize + (numHashes * 0x10));
                // TODO: these are named wrong, they're not numhashes/ciphertext but it's *close*
            }
            if (_header.Npd!.Version >= 2 && str.Position != str.Length)
            {
                byte[] footerBytes = str.ReadBytes(0x10);
                _footer = Encoding.UTF8.GetString(footerBytes);
            }
            Console.WriteLine(_header.Npd.ContentID);
            Console.WriteLine(_header.Npd.AppType);
            Console.WriteLine(_header.Npd.DRMType);
            Console.WriteLine(_header.Flags);
            Console.WriteLine(_footer);
        }
    }
}
