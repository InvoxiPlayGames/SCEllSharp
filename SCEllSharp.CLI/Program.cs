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

string fileName = args[1];
string outputPath = args[2];
Directory.CreateDirectory(outputPath);

FileStream fs = File.OpenRead(fileName);

PKGReader pkg = new PKGReader(fs);
Console.WriteLine(pkg.ContentID);
Console.WriteLine(pkg.GetContentType());
Console.WriteLine(pkg.GetDRMType());
Console.WriteLine(pkg.GetFlags());
Console.WriteLine();
foreach (PKGFile file in pkg.Files)
{
    Console.WriteLine($"{file.Filename} ({file.FileSize} bytes) ({file.Flags})");
    if (file.IsDirectory)
        Directory.CreateDirectory(Path.Combine(outputPath, file.Filename));
    else
        file.ExtractToFile(Path.Combine(outputPath, file.Filename));
}
