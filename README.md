# UnFairPlay

## Requirements
- macOS 11.2.3 or below
- SIP enabled

## Usage
### Build
```
$ gcc unfairplay.c -o unfairplay
```

### Decrypt
```
$ ./unfairplay src dest
```
- Example: `sudo ./unfairplay /Applications/HogeApp.app/Contents/MacOS/HogeApp ./HogeApp.decrypted`

(*) If the decryption fails, you may need to try again a few seconds after.

## Description

Decrypt FairPlay encrypted binaries on macOS when SIP-enabled.

By mapping an executable as r-x and then using mremap_encrypted on the encrypted page(s) and then writing them back out to disk, you can fully decrypt FairPlay binaries.

This was discovered independently when analyzing kernel sources, but it appears that the technique was first introduced on iOS (but now works on macOS): https://github.com/JohnCoates/flexdecrypt

This code is re-write of foulplay in [apple-tools](https://github.com/meme/apple-tools). Thanks to [@meme](https://github.com/meme). 
