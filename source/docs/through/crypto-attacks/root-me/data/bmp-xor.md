# Known plaintext XOR

[RootMe: Known plaintext - XOR](https://www.root-me.org/en/Challenges/Cryptanalysis/Known-plaintext-XOR): This BMP picture was mistakenly encrypted. Can you recover it?

For this challenge you will need to decipher a simple XORed picture.

## Solution

Getting the file and looking at the header with `hexeditor -r ch3.bmp`:

![Header](/_static/images/bmp-encrypted-header.png)

```text
24 2C 9A E3  62 6E 66 61   6C 6C 53 6E  66 61
```

The [Bitmap file header](https://en.wikipedia.org/wiki/BMP_file_format) is encrypted too. I don't know what the unencrypted size will be, so only have the first two bytes plaintext: `0x42 0x4D` for `BM`.

And why make life harder than need be. Install [xortool](https://github.com/hellman/xortool):

```text
pip3 install xortool
Collecting xortool
  Downloading xortool-1.0.2-py3-none-any.whl (11 kB)
Requirement already satisfied: docopt<0.7.0,>=0.6.2 in /usr/lib/python3/dist-packages (from xortool) (0.6.2)
Installing collected packages: xortool
Successfully installed xortool-1.0.2
```

Get the key:

```text
xortool -c 20 ch3.bmp                       
The most probable key lengths:
 1:  10.6%
 3:  11.6%
 6:  18.5%
 9:   8.8%
12:  13.8%
15:   6.6%
18:  10.4%
24:   8.1%
30:   6.4%
36:   5.2%
Key-length can be 3*n
1 possible key(s) of length 6:
FALLEN
Found 0 plaintexts with 95%+ valid characters
See files filename-key.csv, filename-char_used-perc_valid.csv
```                                                                                                  

Decrypt with found key:

```text
xortool-xor -s fallen -f ch3.bmp > flag.bmp
```

Check:

```text
file flag.bmp                    
flag.bmp: PC bitmap, Windows 3.x format, 463 x 356 x 24, image size 495552, resolution 2835 x 2835 px/m, cbSize 495606, bits offset 54
```

And view the decrypted image to get the flag.
