using SCEllSharp.Crypto;
using SCEllSharp.NPDRM;
using System.Buffers.Binary;

namespace SCEllSharp.PKG
{
    public class PKGReader
    {
        private Stream File;
        private PKGHeader Header;
        private PKGExtendedHeader? ExtendedHeader;
        private byte[]? ExtendedData;
        private AES128CTRStream EncryptedData;
        private PKGMetadataEntry[] MetadataEntries;

        public PKGFile[] Files;

        public bool IsPortablePKG => Header.PackageType == 0x0002;

        public string ContentID => Header.ContentID!;

        internal PKGMetadataEntry[] GetMetadataEntries()
        {
            return MetadataEntries;
        }

        public PKGContentType GetContentType()
        {
            foreach (PKGMetadataEntry type in MetadataEntries.Where((entry) => { return entry.Type == PKGMetadataType.ContentType; }))
                return (PKGContentType)BinaryPrimitives.ReadUInt32BigEndian(type.Data);
            return PKGContentType.Unknown;
        }

        public NPDRMType GetDRMType()
        {
            foreach (PKGMetadataEntry type in MetadataEntries.Where((entry) => { return entry.Type == PKGMetadataType.DRMType; }))
                return (NPDRMType)BinaryPrimitives.ReadUInt32BigEndian(type.Data);
            return NPDRMType.Unknown;
        }

        public PKGFlags GetFlags()
        {
            foreach (PKGMetadataEntry type in MetadataEntries.Where((entry) => { return entry.Type == PKGMetadataType.PackageType; }))
                return (PKGFlags)BinaryPrimitives.ReadUInt32BigEndian(type.Data);
            return PKGFlags.None;
        }

        public PKGReader(Stream file)
        {
            file.Position = 0;
            File = file;

            // read the file header and make sure it's actually a valid pkg
            Header = new PKGHeader();
            Header.ReadHeader(File);
            if (Header.PackageMagic != 0x7F504B47)
                throw new Exception("Package magic was not that of a PKG!");
            if (Header.PackageRevision != 0x8000)
                throw new Exception("Package revision was not that of a retail PKG!");
            if (Header.PackageType != 0x0001 && Header.PackageType != 0x0002)
                throw new Exception("Package type was not that of a PS3 or PSP/PSVita PKG!");

            bool isPortable = Header.PackageType == 0x0002;
            
            // verify the integrity of the file header
            byte[] digestbytes = File.ReadBytes(0x40);
            MemoryStream validstream = new MemoryStream(0x80);
            Header.WriteHeader(validstream);
            (bool cmac, bool sig, bool sha1) isPkgValid = PKGDigest.ValidatePKGDigest(validstream.ToArray(), 0x80, digestbytes);

            if (isPortable)
            {
                // read the extended file header
                ExtendedHeader = new PKGExtendedHeader();
                ExtendedHeader.ReadExtHeader(File);
                if (ExtendedHeader.PkgExtMagic != 0x7F657874)
                    throw new Exception("Package extended magic was not that of a PKG!");
                if (ExtendedHeader.PkgExtRevision != 0x00000001)
                    throw new Exception("Package extended revision was not that of a PKG!");
                if (ExtendedHeader.KeyID != 0x00000001)
                    throw new Exception("PS Vita packages are not supported!");
                // TODO: validate the digests from all that
                ExtendedData = File.ReadBytes((int)ExtendedHeader.ExtendedDataSize);
            }

            // read each metadata entry from the pkg file
            MetadataEntries = new PKGMetadataEntry[Header.MetadataCount];
            File.Position = Header.MetadataOffset;
            for (int i = 0; i < Header.MetadataCount; i++)
            {
                MetadataEntries[i] = new PKGMetadataEntry();
                MetadataEntries[i].ReadEntry(File);
            }

            // validate the signature on the metadata bytes
            File.Position = Header.MetadataOffset + Header.MetadataSize;
            byte[] metadigestbytes = File.ReadBytes(0x40);
            MemoryStream metavalidstream = new MemoryStream((int)Header.MetadataSize);
            foreach (PKGMetadataEntry entry in MetadataEntries)
                entry.WriteEntry(metavalidstream);
            metavalidstream.SetLength((int)Header.MetadataSize); // ensure the stream is the right length
            (bool cmac, bool sig, bool sha1) isMetaValid = PKGDigest.ValidatePKGDigest(metavalidstream.ToArray(), (int)Header.MetadataSize - 0x40, metadigestbytes);
            // TODO: make sure this is right, it doesn't seem to be...? i remember it working but maybe i'm an idiot

            // set up the encrypted data stream
            File.Position = (int)Header.DataOffset;
            EncryptedData = new AES128CTRStream(file, PS3Keys.PKGKeyAES, Header.PackageIV!, (long)Header.DataSize);
            if (isPortable) {
                // set up the alternative encryption key
                // TODO: do any PS3 packages do this?
                EncryptedData.AddAltKey(PSPKeys.PKGKeyAES);
                EncryptedData.AltKey = true; // file table uses the alt key
            }

            // read in information about each file
            Files = new PKGFile[Header.NumberOfItems];
            for (int i = 0; i < Header.NumberOfItems; i++)
            {
                PKGFileEntry fileEntry = new PKGFileEntry();
                fileEntry.ReadEntry(EncryptedData);
                Files[i] = new PKGFile(fileEntry, EncryptedData);
            }
        }
    }
}
