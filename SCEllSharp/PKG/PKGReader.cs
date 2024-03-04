using SCEllSharp.Crypto;

namespace SCEllSharp.PKG
{
    public class PKGReader
    {
        public Stream File;
        public PKGHeader Header;
        public AES128CTRStream EncryptedData;
        public PKGFilesystem Filesystem;

        public PKGReader(Stream file)
        {
            File = file;
            Header = new PKGHeader();
            Header.ReadHeader(file);
            if (Header.PackageMagic != 0x7F504B47)
                throw new Exception("Package magic was not that of a PKG!");
            if (Header.PackageRevision != 0x8000)
                throw new Exception("Package revision was not that of a retail PKG!");
            if (Header.PackageType != 0x0001)
                throw new Exception("Package type was not that of a PS3 PKG!");
            // TODO: read metadata entries
            file.Position = (long)Header.DataOffset;
            EncryptedData = new AES128CTRStream(file, PS3Keys.PKGKeyAES, Header.PackageIV!, (long)Header.DataSize);
            Filesystem = new PKGFilesystem(EncryptedData, Header.NumberOfItems);
        }
    }
}
