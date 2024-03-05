using Dorssel.Security.Cryptography;
using SCEllSharp.Crypto;
using System.Security.Cryptography;
using System.Text;

namespace SCEllSharp.PKG
{
    internal class PKGDigest
    {
        /// <summary>
        /// Returns a tuple containing whether the provided PKG digest has a valid AES-CMAC, ECDSA signature, and SHA-1 hash.
        /// </summary>
        /// <param name="data">The data associated with the digest</param>
        /// <param name="length">The length of the data to verify</param>
        /// <param name="digest">The 0x40 byte PKG digest object</param>
        public static (bool, bool, bool) ValidatePKGDigest(byte[] data, int length, byte[] digest)
        {
            AesCmac cmac = new AesCmac(PS3Keys.PKGKeyAES);
            SHA1 sha1 = SHA1.Create();
            byte[] cmac_hash = cmac.ComputeHash(data, 0, length);
            byte[] sha1_hash = sha1.ComputeHash(data, 0, length);
            byte[] last_8_sha1 = sha1_hash.Skip(0x14 - 0x8).ToArray();

            // ew
            byte[] cmac_in_digest = digest.Take(0x10).ToArray();
            byte[] signature_in_digest = digest.Skip(0x10).Take(0x28).ToArray();
            byte[] sha1_in_digest = digest.Skip(0x38).Take(0x8).ToArray();

            bool cmac_valid = cmac_in_digest.SequenceEqual(cmac_hash);
            bool sha1_valid = sha1_in_digest.SequenceEqual(last_8_sha1);

            ECParameters ecp = new ECParameters
            {
                Curve = PS3Keys.VSHCurve2InvECDSA,
                Q = PS3Keys.NPDRMPublicKeyECDSA
            };
            ECDsa dsa = ECDsa.Create(ecp);
            bool signature_valid = dsa.VerifyHash(sha1_hash, signature_in_digest);

            return (cmac_valid, signature_valid, sha1_valid);
        }

        /// <summary>
        /// Returns a fake-signed PKG digest object of the provided data.
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="length">The length of the data to sign</param>
        public static byte[] GeneratePKGDigest(byte[] data, int length)
        {
            byte[] digest = new byte[0x40];
            AesCmac cmac = new AesCmac(PS3Keys.PKGKeyAES);
            SHA1 sha1 = SHA1.Create();
            byte[] cmac_hash = cmac.ComputeHash(data, 0, length);
            // can we generate valid pkg signatures?
            byte[] signature = Encoding.UTF8.GetBytes("Sony says PSN go byebye, always on NPDRM");
            byte[] sha1_hash = sha1.ComputeHash(data, 0, length);
            Array.Copy(cmac_hash, 0, digest, 0, 0x10);
            Array.Copy(signature, 0, digest, 0x10, 0x28);
            Array.Copy(sha1_hash, 0x14 - 0x8, digest, 0x38, 0x8);
            return digest;
        }
    }
}
