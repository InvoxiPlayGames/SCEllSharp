# SCEllSharp

A work-in-progress .NET 8.0 library for reading and writing file formats used
on the PS3, PSP and PS Vita consoles. (and PS4, if you count PARAM.SFO)

**Current feature set:**

* Read and write encrypted retail PS3 PKG files.
    * Faster than Sony's SDK!
    * Able to verify signatures (on Windows)
* Read encrypted retail PSP PKG files.
    * Work in progress, might be unreliable...
    * This might have added regressions to the above. Oops.
* Read and write PARAM.SFO files.

## Used by...

* [Rock Band 3 Deluxe](https://rb3dx.milohax.org) (via 
  [RB3DXBuildPkgPS3](https://github.com/InvoxiPlayGames/RB3DXBuildPkgPS3))
    * Used to build retail compatible PKG files in CI/CD.

## Documentation

TODO.

## Credits

* [PS3 Developer Wiki](https://www.psdevwiki.com/ps3/)
* [HENkaku Vita Developer Wiki](https://wiki.henkaku.xyz/vita/)
* [RPCS3](https://github.com/RPCS3/rpcs3)
