namespace SCEllSharp.SFO
{
    public enum SFODataFormat : short
    {
        UTF8 = 0x0204,
        Int32 = 0x0404
    }

    public class SFOKey
    {
        public string? Name;
        public int TotalLength;
        public int MaxLength;
        public SFODataFormat Type;

        public string? UTF8String;
        public int Int32Value;

        public override string ToString()
        {
            return $"{Name!} - " + (Type == SFODataFormat.UTF8 ? UTF8String! : Int32Value.ToString());
        }
    }
}
