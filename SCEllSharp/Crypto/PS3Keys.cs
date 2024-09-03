﻿using System.Security.Cryptography;

namespace SCEllSharp.Crypto
{
    public class PS3Keys
    {
        /// <summary>
        /// AES-128-CTR key used to encrypt and decrypt NPDRM PKG files.
        /// AES-128-CMAC key used to generate a hash of PKG header files.
        /// </summary>
        public static readonly byte[] PKGKeyAES =
            { 0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E, 0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8 };

        /// <summary>
        /// AES-128-CMAC key used to generate a hash of content ID + filename in NPDRM protected files.
        /// </summary>
        public static readonly byte[] NPDRMContentHashKeyAES =
            { 0x9B, 0x51, 0x5F, 0xEA, 0xCF, 0x75, 0x06, 0x49, 0x81, 0xAA, 0x60, 0x4D, 0x91, 0xA5, 0x4E, 0x97 };

        /// <summary>
        /// XOR key, XORed with the klicensee, to generate a AES-128-CMAC hash of the NPD header in NPDRM files.
        /// </summary>
        public static readonly byte[] NPDRMHeaderHashKeyXOR =
            { 0x6B, 0xA5, 0x29, 0x76, 0xEF, 0xDA, 0x16, 0xEF, 0x3C, 0x33, 0x9F, 0xB2, 0x97, 0x1E, 0x25, 0x6B };

        /// <summary>
        /// Klicensee used for NPDRM "Free" content type.
        /// </summary>
        public static readonly byte[] NPDRMFreeKlicensee =
            { 0x72, 0xF9, 0x90, 0x78, 0x8F, 0x9C, 0xFF, 0x74, 0x57, 0x25, 0xF0, 0x8E, 0x4C, 0x12, 0x83, 0x87 };


        /// <summary>
        /// ECDSA curve used for validating signatures of almost everything. Inverted from curve 2 of the VSH.
        /// </summary>
        public static readonly ECCurve VSHCurve2InvECDSA = new ECCurve
        {
            CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass,
            Prime = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            A = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC],
            B = [0xA6, 0x8B, 0xED, 0xC3, 0x34, 0x18, 0x02, 0x9C, 0x1D, 0x3C, 0xE3, 0x3B, 0x9A, 0x32, 0x1F, 0xCC, 0xBB, 0x9E, 0x0F, 0x0B],
            Order = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xB5, 0xAE, 0x3C, 0x52, 0x3E, 0x63, 0x94, 0x4F, 0x21, 0x27],
            Cofactor = [0x01],
            G = new ECPoint
            {
                X = [0x12, 0x8E, 0xC4, 0x25, 0x64, 0x87, 0xFD, 0x8F, 0xDF, 0x64, 0xE2, 0x43, 0x7B, 0xC0, 0xA1, 0xF6, 0xD5, 0xAF, 0xDE, 0x2C],
                Y = [0x59, 0x58, 0x55, 0x7E, 0xB1, 0xDB, 0x00, 0x12, 0x60, 0x42, 0x55, 0x24, 0xDB, 0xC3, 0x79, 0xD5, 0xAC, 0x5F, 0x4A, 0xDF]
            }
        };

        /// <summary>
        /// ECDSA key used to validate the signature of NPDRM PKG and EBOOT files. (Use with VSHCurve2InvECDSA)
        /// </summary>
        public static readonly ECPoint NPDRMPublicKeyECDSA = new ECPoint
        {
            X = [0xE6, 0x79, 0x2E, 0x44, 0x6C, 0xEB, 0xA2, 0x7B, 0xCA, 0xDF, 0x37, 0x4B, 0x99, 0x50, 0x4F, 0xD8, 0xE8, 0x0A, 0xDF, 0xEB],
            Y = [0x3E, 0x66, 0xDE, 0x73, 0xFF, 0xE5, 0x8D, 0x32, 0x91, 0x22, 0x1C, 0x65, 0x01, 0x8C, 0x03, 0x8D, 0x38, 0x22, 0xC3, 0xC9]
        };

        /// <summary>
        /// ECDSA key used to validate the signature of NPDRM activation and EDAT files. (Use with VSHCurve2InvECDSA)
        /// </summary>
        public static readonly ECPoint NPDRMActivationPublicKeyECDSA = new ECPoint
        {
            X = [0x62, 0x27, 0xB0, 0x0A, 0x02, 0x85, 0x6F, 0xB0, 0x41, 0x08, 0x87, 0x67, 0x19, 0xE0, 0xA0, 0x18, 0x32, 0x91, 0xEE, 0xB9],
            Y = [0x6E, 0x73, 0x6A, 0xBF, 0x81, 0xF7, 0x0E, 0xE9, 0x16, 0x1B, 0x0D, 0xDE, 0xB0, 0x26, 0x76, 0x1A, 0xFF, 0x7B, 0xC8, 0x5B]
        };
    }
}
