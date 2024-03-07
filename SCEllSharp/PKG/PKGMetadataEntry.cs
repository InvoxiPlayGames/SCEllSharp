namespace SCEllSharp.PKG
{
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
