using System.Text;

namespace SCEllSharp.PKG
{
    public class PKGFile
    {
        public readonly string Filename;
        public readonly PKGFileFlags Flags;
        public readonly int FileSize;
        private int StreamOffset;
        private Stream? FileData;

        public bool IsDirectory => Flags.HasFlag(PKGFileFlags.Directory);

        internal PKGFile(PKGFileEntry entry, Stream basestream)
        {
            FileSize = (int)entry.DataSize;
            StreamOffset = (int)entry.DataOffset;
            Flags = entry.Flags;
            FileData = basestream;

            // read in the filename from the data stream
            long currentPos = basestream.Position;
            byte[] filenameBytes = new byte[entry.FilenameSize];
            basestream.Position = entry.FilenameOffset;
            basestream.Read(filenameBytes, 0, (int)entry.FilenameSize);
            basestream.Position = currentPos;
            Filename = Encoding.ASCII.GetString(filenameBytes);
        }

        public PKGFile(string filename, PKGFileFlags flags, Stream fileData, int fileSize, int streamOffset)
        {
            Filename = filename;
            Flags = flags;
            FileSize = fileSize;
            StreamOffset = streamOffset;
            FileData = fileData;
        }

        public PKGFile(string filename, PKGFileFlags flags, Stream fileData)
        {
            Filename = filename;
            Flags = flags;
            FileSize = (int)fileData.Length;
            StreamOffset = 0;
            FileData = fileData;
        }

        public PKGFile(string filename, PKGFileFlags flags)
        {
            Filename = filename;
            Flags = flags;
        }

        public void ExtractToFile(string filename)
        {
            byte[] buffer = new byte[0x4000];
            int bytesToRead = FileSize;
            int bytesRead = 0;
            FileStream fs = File.Open(filename, FileMode.OpenOrCreate, FileAccess.Write);
            while (bytesToRead > 0)
            {
                int r = ReadData(buffer, bytesRead, bytesToRead > buffer.Length ? buffer.Length : bytesToRead);
                fs.Write(buffer, 0, r);
                bytesRead += r;
                bytesToRead -= r;
            }
            fs.Close();
        }

        public int ReadData(byte[] buffer, int offset_in_file, int length)
        {
            if (Flags.HasFlag(PKGFileFlags.Directory))
                throw new Exception("Can't read file data from a directory!");

            if (FileData == null)
                throw new Exception("File has no base stream!");

            FileData!.Seek(offset_in_file + StreamOffset, SeekOrigin.Begin);
            int r = FileData!.Read(buffer, 0, length);
            return r;
        }
    }
}
