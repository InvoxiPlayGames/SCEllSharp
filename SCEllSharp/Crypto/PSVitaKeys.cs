using System.Security.Cryptography;

namespace SCEllSharp.Crypto
{
    public class PSVitaKeys
    {
        /// <summary>
        /// AES-128-ECB key used to derive the decryption key for NPDRM PS Vita PKG files.
        /// </summary>
        public static readonly byte[] PKGKeyVitaAES =
            { 0xE3, 0x1A, 0x70, 0xC9, 0xCE, 0x1D, 0xD7, 0x2B, 0xF3, 0xC0, 0x62, 0x29, 0x63, 0xF2, 0xEC, 0xCB };

        /// <summary>
        /// AES-128-ECB key used to derive the decryption key for NPDRM LiveArea PKG files.
        /// </summary>
        public static readonly byte[] PKGKeyLiveAreaAES =
            { 0x42, 0x3A, 0xCA, 0x3A, 0x2B, 0xD5, 0x64, 0x9F, 0x96, 0x86, 0xAB, 0xAD, 0x6F, 0xD8, 0x80, 0x1F };

        /// <summary>
        /// AES-128-ECB key used to derive the decryption key for NPDRM PSM PKG files.
        /// </summary>
        public static readonly byte[] PKGKeyPSMAES =
            { 0xAF, 0x07, 0xFD, 0x59, 0x65, 0x25, 0x27, 0xBA, 0xF1, 0x33, 0x89, 0x66, 0x8B, 0x17, 0xD9, 0xEA };
    }
}
