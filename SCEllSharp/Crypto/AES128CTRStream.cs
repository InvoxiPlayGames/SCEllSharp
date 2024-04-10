using System.Security.Cryptography;

namespace SCEllSharp.Crypto
{
    public class AES128CTRStream : Stream
    {
        private Stream _stream;
        private byte[] _iv;
        private byte[] _key;
        private long _position;
        private long _startPosition;

        private bool _hasLength;
        private long _length;

        // managed AES-128-ECB context
        private Aes _aes;
        private ICryptoTransform _aesEncryptor;
        // current counter for AES-128-CTR
        private byte[] _counter = new byte[0x10];

        /// <summary>
        /// Creates a stream for encrypting and decrypting contents with an AES-128-CTR algorithm.
        /// </summary>
        /// <param name="original">Original stream to read/write from</param>
        /// <param name="key">The encryption key to use</param>
        /// <param name="iv">The initialisation vector for encryption</param>
        public AES128CTRStream(Stream original, byte[] key, byte[] iv)
        {
            _position = 0;

            // set up our reference to the original stream
            _stream = original;
            _startPosition = original.Position;

            // set up our encryption context
            _key = key;
            _iv = iv;
            // use AES-128-ECB as a base for our CTR algorithm (see UpdatePosition/IncrementCounter)
            _aes = Aes.Create();
            _aes.BlockSize = 128;
            _aes.Mode = CipherMode.ECB;
            _aes.Key = _key;
            _aes.IV = new byte[0x10]; // blank IV for the ECB
            _aes.Padding = PaddingMode.None;
            _aesEncryptor = _aes.CreateEncryptor();
        }

        /// <summary>
        /// Creates a stream of a given length for decrypting contents with an AES-128-CTR algorithm.
        /// </summary>
        /// <param name="original">Original stream to read/write from</param>
        /// <param name="key">The encryption key to use</param>
        /// <param name="iv">The initialisation vector for encryption</param>
        /// <param name="length">The maximum length of contents that can be read</param>
        public AES128CTRStream(Stream original, byte[] key, byte[] iv, long length) : this(original, key, iv)
        {
            _hasLength = true;
            _length = length;
        }

        public override bool CanRead => _position < Length && _position >= 0;

        public override bool CanSeek => true;

        public override long Length { get => _hasLength ? _length : _stream.Length - _startPosition; }

        public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }

        private void IncrementCounter(byte[] counter)
        {
            // increment the counter as if it was a big endian 128-bit integer
            for (int i = 0xF; i >= 0; i--)
                if (++counter[i] != 0)
                    break;
        }

        private void UpdatePosition(long position)
        {
            int block_num = (int)(position / 0x10);
            Buffer.BlockCopy(_iv, 0, _counter, 0, 0x10);
            for (int i = 0; i < block_num; i++)
                IncrementCounter(_counter);
            return;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int offset_into_block = (int)(_position % 0x10);
            int block_count = (count / 0x10) + 1;

            // read from the file into the buffer (reading encrypted contents)
            int bytes_read = _stream.Read(buffer, offset, count);
            int bytes_crypt = 0;

            byte[] cryptstream = new byte[0x10];
            UpdatePosition(_position); // make sure our original counter is correct
            for (int i = 0; i < block_count; i++)
            {
                // generate our XOR stream for the CTR
                _aesEncryptor.TransformBlock(_counter, 0, 0x10, cryptstream, 0);
                for (int j = offset_into_block; j < 0x10 && bytes_crypt < bytes_read; j++, bytes_crypt++)
                    buffer[offset + bytes_crypt] ^= cryptstream[j];

                // if we're going into a new block, don't offset anymore and increment our counter
                offset_into_block = 0;
                if (bytes_read > bytes_crypt)
                    IncrementCounter(_counter);
            }

            // increment our stream's position
            _position += bytes_read;

            return bytes_read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            // if we're seeking from the start, offset from our base stream's position
            if (origin == SeekOrigin.Begin)
                offset += _startPosition;
            long seeked = _stream.Seek(offset, origin);
            _position = seeked - _startPosition;
            return seeked;
        }

        public override bool CanWrite => true;

        public override void Flush()
        {
            _stream.Flush();
        }

        public override void SetLength(long value)
        {
            _stream.SetLength(value + _startPosition);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int offset_into_block = (int)(_position % 0x10);
            int block_count = (count / 0x10) + 1;

            // read from the file into the buffer (reading encrypted contents)
            int bytes_crypt = 0;
            int bytes_left = buffer.Length < count ? buffer.Length : count;

            byte[] cryptstream = new byte[0x10];
            UpdatePosition(_position); // make sure our original counter is correct
            for (int i = 0; i < block_count; i++)
            {
                // generate our XOR stream for the CTR
                _aesEncryptor.TransformBlock(_counter, 0, 0x10, cryptstream, 0);

                int crypt_count = bytes_left < 0x10
                    ? bytes_left > (0x10 - offset_into_block)
                    ? 0x10 - offset_into_block
                    : bytes_left
                    : 0x10 - offset_into_block;
                for (int j = offset_into_block; j < offset_into_block + crypt_count; j++) {
                    cryptstream[j] ^= buffer[offset + bytes_crypt];
                    bytes_crypt++;
                }

                _stream.Write(cryptstream, offset_into_block, crypt_count);

                bytes_left -= 0x10;
                if (bytes_left < 0) bytes_left = 0;

                // if we're going into a new block, don't offset anymore and increment our counter
                offset_into_block = 0;
                IncrementCounter(_counter);
            }

            // increment our stream's position
            _position += count;

            return;
        }
    }
}
