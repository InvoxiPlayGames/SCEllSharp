using SCEllSharp.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SCEllSharp.PKG
{
    public class PKGWriter
    {
        public string ContentID;
        private List<PKGFile> Files;
        private List<PKGMetadataEntry> MetadataEntries;

        public PKGWriter(string contentID)
        {
            ContentID = contentID;
            Files = new List<PKGFile>();
            MetadataEntries = new List<PKGMetadataEntry>();
        }

        public PKGWriter(PKGReader reader)
        {
            ContentID = reader.ContentID;
            Files = new List<PKGFile>();
            MetadataEntries = new List<PKGMetadataEntry>();
            foreach (PKGFile file in reader.Files)
                Files.Add(file);
            foreach (PKGMetadataEntry entry in reader.GetMetadataEntries())
                MetadataEntries.Add(entry);
        }

        public void WritePKG(Stream stream)
        {
            // wrap everything except the final output in a SHA-1 stream
            SHA1WriteStream outer = new SHA1WriteStream(stream);

            long fileDataSize = 0;
            long filenameTableSize = 0;
            long fileEntryTableSize = 0;
            foreach(PKGFile file in Files)
            {
                // 0x20 for the file entry
                fileEntryTableSize += 0x20;
                filenameTableSize += file.Filename.Length + (file.Filename.Length % 0x10);
                fileDataSize += file.FileSize + (file.FileSize % 0x10);
            }
            long encryptedBodySize = fileEntryTableSize + filenameTableSize + fileDataSize;

            uint totalMetadataSize = 0x40; // for the signed footer
            foreach (PKGMetadataEntry entry in MetadataEntries)
                totalMetadataSize += entry.TotalSize;

            long totalPkgSize = 0xC0 + totalMetadataSize + encryptedBodySize + 0x20; // 0xC0 - header, 0x20 - footer

            // build the PKG header
            PKGHeader header = new();
            header.PackageMagic = 0x7F504B47;
            header.PackageRevision = 0x8000;
            header.PackageType = 0x0001;
            header.MetadataOffset = 0xC0; // always here
            header.MetadataCount = (uint)MetadataEntries.Count;
            header.MetadataSize = totalMetadataSize;
            header.NumberOfItems = (uint)Files.Count;
            header.TotalPackageSize = (uint)totalPkgSize;
            header.DataOffset = 0xC0 + totalMetadataSize;
            header.DataSize = (ulong)encryptedBodySize;
            header.ContentID = ContentID;
            header.DebugDigest = new byte[0x10];
            header.PackageIV = new byte[0x10];

            // write it out to a MemoryStream to generate a digest
            MemoryStream headerStr = new MemoryStream(0xC0);
            header.WriteHeader(headerStr);
            byte[] headerDigest = PKGDigest.GeneratePKGDigest(headerStr.ToArray(), 0x80);
            headerStr.Write(headerDigest);
            // write out the header to the file
            outer.Write(headerStr.ToArray());
            headerStr.Dispose();

            // build out the metadata table, generate a digest and write it out
            MemoryStream metaStr = new MemoryStream((int)totalMetadataSize);
            foreach (PKGMetadataEntry entry in MetadataEntries)
                entry.WriteEntry(metaStr);
            byte[] metaDigest = PKGDigest.GeneratePKGDigest(metaStr.ToArray(), (int)totalMetadataSize - 0x40);
            metaStr.Write(metaDigest);
            outer.Write(metaStr.ToArray());
            metaStr.Dispose();

            //outer.Flush();

            // start an encrypted stream
            AES128CTRStream enc = new AES128CTRStream(outer, PS3Keys.PKGKeyAES, header.PackageIV);

            // prepare the file entry and filename tables
            int filenameTableBytesUsed = 0;
            long totalFileOffsetUsed = 0;
            byte[] filenameTable = new byte[filenameTableSize];
            foreach(PKGFile file in Files)
            {
                PKGFileEntry entry = new PKGFileEntry();
                byte[] filenameBytes = Encoding.ASCII.GetBytes(file.Filename);
                entry.FilenameOffset = (uint)(fileEntryTableSize + filenameTableBytesUsed);
                entry.DataOffset = (ulong)(fileEntryTableSize + filenameTableSize + totalFileOffsetUsed);
                entry.FilenameSize = (uint)filenameBytes.Length;
                entry.DataSize = (ulong)file.FileSize;
                entry.Flags = file.Flags;
                Array.Copy(filenameBytes, 0, filenameTable, filenameTableBytesUsed, filenameBytes.Length);
                filenameTableBytesUsed += filenameBytes.Length + (filenameBytes.Length % 0x10);
                totalFileOffsetUsed += file.FileSize + (file.FileSize % 0x10);
                // write the entry
                entry.WriteEntry(enc);
            }
            // write the filename table
            enc.Write(filenameTable);

            // write the file data
            foreach(PKGFile file in Files)
            {
                Console.WriteLine(file.Filename);
                byte[] buffer = new byte[0x4000];
                int bytesToRead = file.FileSize;
                int bytesRead = 0;
                while (bytesToRead > 0)
                {
                    int r = file.ReadData(buffer, bytesRead, bytesToRead > buffer.Length ? buffer.Length : bytesToRead);
                    Console.WriteLine(r);
                    enc.Write(buffer, 0, r);
                    bytesRead += r;
                    bytesToRead -= r;
                }
                if ((file.FileSize % 0x10) > 0)
                {
                    Console.WriteLine(file.FileSize % 0x10);
                    byte[] filepadding = new byte[(file.FileSize % 0x10)];
                    enc.Write(filepadding, 0, filepadding.Length);
                }
            }

            // write the final SHA-1
            byte[] finalShaHash = outer.GetSHA1Hash()!;
            byte[] padding = new byte[0xC];
            stream.Write(finalShaHash);
            stream.Write(padding);

            stream.Flush();
        }

    }
}
