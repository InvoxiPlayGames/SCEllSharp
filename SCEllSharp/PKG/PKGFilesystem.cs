using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SCEllSharp.PKG
{
    public class PKGFile
    {
        public string Filename;
        public ulong DataOffset;
        public ulong DataSize;
        public uint Flags;
        public uint Unknown;

        public bool IsDirectory => (Flags & 0x4) == 0x4;

        public PKGFile(Stream entry)
        {
            uint FilenameOffset = entry.ReadUInt32BE();
            uint FilenameSize = entry.ReadUInt32BE();
            DataOffset = entry.ReadUInt64BE();
            DataSize = entry.ReadUInt64BE();
            Flags = entry.ReadUInt32BE();
            Unknown = entry.ReadUInt32BE();

            long currentPos = entry.Position;
            entry.Position = FilenameOffset;
            byte[] FilenameBytes = new byte[FilenameSize];
            entry.Read(FilenameBytes);
            Filename = Encoding.UTF8.GetString(FilenameBytes);
            entry.Position = currentPos;
        }
    }

    public class PKGFilesystem
    {
        private Stream _stream;
        public PKGFile[] Files;

        public PKGFilesystem(Stream fs, uint filecount)
        {
            _stream = fs;
            Files = new PKGFile[filecount];
            for (int i = 0; i < filecount; i++)
                Files[i] = new PKGFile(fs);
        }

        public void ExtractFile(PKGFile file, string output_path)
        {
            using (FileStream output = File.Open(output_path, FileMode.CreateNew)) {
                byte[] readBuffer = new byte[0x8000];
                int readBytes = 0;
                int remaining = (int)file.DataSize;
                // seek to the start of the file data in here
                _stream.Seek((long)file.DataOffset, SeekOrigin.Begin);
                int bytesToRead = remaining > readBuffer.Length ? readBuffer.Length : remaining;
                while ((readBytes = _stream.Read(readBuffer, 0, bytesToRead)) > 0)
                {
                    output.Write(readBuffer, 0, readBytes);
                    remaining -= readBytes;
                    bytesToRead = remaining > readBuffer.Length ? readBuffer.Length : remaining;
                }
            }
        }
    }
}
