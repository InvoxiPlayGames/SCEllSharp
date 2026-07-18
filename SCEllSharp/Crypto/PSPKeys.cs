using System.Security.Cryptography;

namespace SCEllSharp.Crypto
{
    public class PSPKeys
    {
        /// <summary>
        /// AES-128-CTR key used to encrypt and decrypt NPDRM PKG files.
        /// AES-128-CMAC key used to generate a hash of PKG header files.
        /// </summary>
        public static readonly byte[] PKGKeyAES =
            { 0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B };
    }
}