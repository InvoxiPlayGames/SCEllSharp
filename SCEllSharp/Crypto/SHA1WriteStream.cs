using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SCEllSharp.Crypto
{
    public class SHA1WriteStream : Stream
    {
        private SHA1 _sha1;
        private Stream _base;

        public SHA1WriteStream(Stream stream)
        {
            _base = stream;
            _sha1 = SHA1.Create();
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => _base.Length;

        public override long Position { get => _base.Position; set => throw new NotImplementedException(); }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public byte[]? GetSHA1Hash()
        {
            byte[] nothing = Array.Empty<byte>();
            _sha1.TransformFinalBlock(nothing, 0, 0);
            return _sha1.Hash;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _base.Write(buffer, offset, count);
            _sha1.TransformBlock(buffer, offset, count, null, 0);
        }
    }
}
