**This script was proof of concept and is no longer under active development. It remains here as an example for how to do much of the eShop's functionality in an external tool, but is in no way polished.**

___

You're on your own for the keys

**Requires [makerom](https://github.com/profi200/Project_CTR/releases), [ctr-common-1.crt and ctr-common-1.key](https://plailect.github.io/Guide/torrents/ctr-common-1.torrent) to be in the directory**   
___

This script is **proof of concept** tool that uses **decrypted** titlekeys from **decTitleKeys.bin**. For a more feature complete tool that uses **encrypted** titlekeys and **encTitleKeys.bin** then use [@Cruel's tool](https://github.com/Cruel/freeShop) instead.

Until such time as the bootrom and its relevant keys (0x3D KeyX to be specific) have been obtained, you will have to choose between encrypted and decrypted titlekeys since we cannot encrypt/decrypt them from a PC yet.

To convert between them on a 3DS, use [Decrypt9WIP](https://github.com/d0k3/Decrypt9WIP).
___

Usage: PlaiCDN \<TitleID TitleKey\> \<Options\> for content options    
\-redown   : redownload content    
\-no3ds    : don't build 3DS file    
\-nocia    : don't build CIA file    
\-nobuild  : don't build 3DS or CIA    
\-nohash   : ignore hash checks        
\-check    : checks if title id matches key    
\-fast     : skips name retrieval when using -check    

Usage: PlaiCDN \<TitleID\> for general options    
\-info     : to display detailed metadata    
\-seed     : generates game-specific seeddb file when using -info    

Usage: PlaiCDN \<Options\> for decTitleKeys.bin options    
\-deckey   : print keys from decTitleKeys.bin    
\-checkbin : checks titlekeys from decTitleKeys.bin    
\-checkall : check all titlekeys when using -checkbin    
\-fast     : skips name retrieval when using -checkbin, cannot be used with seed/seeddb    
\-seeddb   : generates a single seeddb.bin    

___

Examples (note this is not the correct key):    
+ `PlaiCDN.exe 000400000014F200 -info`
  + this would pull a ton of title metadata off the CDN for "Animal Crossing: Happy Home Designer"
+ `PlaiCDN.exe 000400000014F200 abb5c65ecaba9bcd29d1bfdf3f64c285`
  + this would create a .CIA and .3DS file for "Animal Crossing: Happy Home Designer"
+ `PlaiCDN.exe 000400000014F200 abb5c65ecaba9bcd29d1bfdf3f64c285 -check`
  + this would check if the key (abb5c65ecaba9bcd29d1bfdf3f64c285) for "Animal Crossing: Happy Home Designer" is correct (it's not)
+ `PlaiCDN.exe 000400000014F200 abb5c65ecaba9bcd29d1bfdf3f64c285 -redown -no3ds`
  + this would create a .CIA file after redownloading previously downloaded encrypted files for "Animal Crossing: Happy Home Designer"
+ `PlaiCDN.exe -checkbin`
  + this would check all game keys in `decTitleKeys.bin` to see if they match their titles, in addition to outputting metadata on them pulled from the CDN

___

If pycrypto gives you issues installing, try using [this](https://github.com/sfbahr/PyCrypto-Wheels).

The executable was created with the command `pyinstaller --onefile PlaiCDN.py`

This project is a replacement for [CDNto3DS](https://github.com/Relys/3DS_Multi_Decryptor/blob/master/to3DS/CDNto3DS/CDNto3DS.py) and includes expanded features and capabilities, including use on non windows platforms thanks to its reliance on PyCrypto instead of aescbc.

___

Example Output:

![screenshot](http://i.imgur.com/MuT7FX6.png)
