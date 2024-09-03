using Dorssel.Security.Cryptography;
using SCEllSharp.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SCEllSharp.NPDRM
{
    public class NPD
    {
        public uint Magic;
        public uint Version;
        public NPDRMType DRMType;
        public NPDRMAppType AppType;
        public string? ContentID;
        public byte[]? QADigest;
        public byte[]? ContentIDHash;
        public byte[]? HeaderHash;
        public ulong LimitedTimeStart;
        public ulong LimitedTimeEnd;

        public NPD(string content_id, NPDRMType drm_type, NPDRMAppType app_type = NPDRMAppType.Module, byte[]? qa_digest = null)
        {
            Magic = 0x4E504400;
            Version = 4;
            DRMType = drm_type;
            AppType = app_type;
            ContentID = content_id;
            if (qa_digest == null)
                QADigest = new byte[0x10];
            else
                QADigest = qa_digest;
            ContentIDHash = new byte[0x10];
            HeaderHash = new byte[0x10];
            LimitedTimeStart = 0;
            LimitedTimeEnd = 0;
        }

        internal NPD()
        {

        }

        public void Read(Stream stream)
        {
            Magic = stream.ReadUInt32BE();
            Version = stream.ReadUInt32BE();
            DRMType = (NPDRMType)stream.ReadUInt32BE();
            AppType = (NPDRMAppType)stream.ReadUInt32BE();
            byte[] ContentIDBytes = stream.ReadBytes(0x30);
            ContentID = Encoding.UTF8.GetString(ContentIDBytes);
            QADigest = stream.ReadBytes(0x10);
            ContentIDHash = stream.ReadBytes(0x10);
            HeaderHash = stream.ReadBytes(0x10);
            LimitedTimeStart = stream.ReadUInt64BE();
            LimitedTimeEnd = stream.ReadUInt64BE();
        }

        public void Write(Stream stream, bool partial = false)
        {
            stream.WriteUInt32BE(Magic);
            stream.WriteUInt32BE(Version);
            stream.WriteUInt32BE((uint)DRMType);
            stream.WriteUInt32BE((uint)AppType);
            // pad out content ID to 0x30 bytes
            byte[] ContentIDBytes = new byte[0x30];
            byte[] ContentIDASCII = Encoding.UTF8.GetBytes(ContentID!);
            Array.Copy(ContentIDASCII, ContentIDBytes, ContentIDASCII.Length);
            stream.Write(ContentIDBytes, 0, 0x30);
            stream.Write(QADigest!, 0, 0x10);
            stream.Write(ContentIDHash!, 0, 0x10);
            // when calculating signatures the next few fields aren't used
            if (partial) return;
            stream.Write(HeaderHash!, 0, 0x10);
            stream.WriteUInt64BE(LimitedTimeStart);
            stream.WriteUInt64BE(LimitedTimeEnd);
        }

        public bool IsHeaderValid(byte[] klicensee, string filename)
        {
            AesCmac cid_cmac = new AesCmac(PS3Keys.NPDRMContentHashKeyAES);
            // CMAC(ContentID + Filename), ContentID is padded to 0x30 bytes
            byte[] FilenameASCII = Encoding.UTF8.GetBytes(filename);
            byte[] ContentIDASCII = Encoding.UTF8.GetBytes(ContentID!);
            byte[] CID_FN_Data = new byte[0x30 + FilenameASCII.Length];
            Array.Copy(ContentIDASCII, 0, CID_FN_Data, 0, ContentIDASCII.Length);
            Array.Copy(FilenameASCII, 0, CID_FN_Data, 0x30, FilenameASCII.Length);
            byte[] expected_cid_hash = cid_cmac.ComputeHash(CID_FN_Data);
            if (!ContentIDHash!.SequenceEqual(expected_cid_hash))
                return false;

            // write a partial header to a new memory buffer
            MemoryStream ms = new(0x60);
            this.Write(ms, true);
            ms.Position = 0;

            // generate the key used for the header hash
            byte[] header_hash_key = new byte[0x10];
            for (int i = 0; i < 0x10; i++)
                header_hash_key[i] = (byte)(klicensee[i] ^ PS3Keys.NPDRMHeaderHashKeyXOR[i]);
            AesCmac header_cmac = new AesCmac(header_hash_key);
            byte[] expected_header_hash = header_cmac.ComputeHash(ms.ReadBytes(0x60));
            if (!HeaderHash!.SequenceEqual(expected_header_hash))
                return false;

            return true;
        }

        public void HashHeader(byte[] klicensee, string filename)
        {
            AesCmac cid_cmac = new AesCmac(PS3Keys.NPDRMContentHashKeyAES);
            // CMAC(ContentID + Filename), ContentID is padded to 0x30 bytes
            byte[] FilenameASCII = Encoding.UTF8.GetBytes(filename);
            byte[] ContentIDASCII = Encoding.UTF8.GetBytes(ContentID!);
            byte[] CID_FN_Data = new byte[0x30 + FilenameASCII.Length];
            Array.Copy(ContentIDASCII, 0, CID_FN_Data, 0, ContentIDASCII.Length);
            Array.Copy(FilenameASCII, 0, CID_FN_Data, 0x30, FilenameASCII.Length);
            ContentIDHash = cid_cmac.ComputeHash(CID_FN_Data);

            // write a partial header to a new memory buffer
            MemoryStream ms = new(0x60);
            this.Write(ms, true);
            ms.Position = 0;

            // generate the key used for the header hash
            byte[] header_hash_key = new byte[0x10];
            for (int i = 0; i < 0x10; i++)
                header_hash_key[i] = (byte)(klicensee[i] ^ PS3Keys.NPDRMHeaderHashKeyXOR[i]);
            AesCmac header_cmac = new AesCmac(header_hash_key);
            HeaderHash = header_cmac.ComputeHash(ms.ReadBytes(0x60));
        }

        public static NPD ReadNew(Stream stream)
        {
            NPD npd = new NPD();
            npd.Read(stream);
            return npd;
        }
    }
}
