namespace SCEllSharp.NPDRM
{
    public enum NPDRMType
    {
        Unknown = 0,
        Network = 1,
        Local = 2,
        Free = 3
    }

    public enum NPDRMAppType
    {
        Module = 0x00,
        Executable = 0x01,
        ModuleDisc = 0x20,
        ExecutableDisc = 0x21,
        ModuleHDD = 0x30,
        ExecutableHDD = 0x31
    }
}
