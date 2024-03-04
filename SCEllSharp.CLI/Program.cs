using SCEllSharp.PKG;

if (args.Length < 3)
{
    Console.WriteLine("usage: ./SCEllSharp.CLI ExtractPKG /path/to/your/pkg /path/to/output");
    return;
}

if (args[0] != "ExtractPKG")
{
    Console.WriteLine("unknown option - valid option is only ExtractPKG");
    return;
}

string outputPath = args[2];
Directory.CreateDirectory(outputPath);

FileStream fs = File.OpenRead(args[1]);

PKGReader pkg = new PKGReader(fs);
Console.WriteLine(pkg.Header.ContentID);
foreach(PKGFile file in pkg.Filesystem.Files)
{
    Console.WriteLine($"{file.Filename} ({file.DataSize} bytes) ({file.Flags:x8})");
    if (file.IsDirectory)
        Directory.CreateDirectory(Path.Combine(outputPath, file.Filename));
    else
        pkg.Filesystem.ExtractFile(file, Path.Combine(outputPath, file.Filename));
}

//AesCmac a = new AesCmac(PS3Keys.PKGKeyAES);
//a.ComputeHash(header)

//ECParameters ecp = new ECParameters
//{
//    Curve = PS3Keys.VSHCurve2InvECDSA,
//    Q = PS3Keys.NPDRMPublicKeyECDSA
//};
//ECDsa dsa = ECDsa.Create(ecp);
//Console.WriteLine(dsa.VerifyHash(sha1, signature));
