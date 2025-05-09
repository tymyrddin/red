# PNG LSB

[root-me challenge](https://www.root-me.org/en/Challenges/Steganography/PNG-Least-Significant-Bit): Uncle Scrooge does not only love gold, seems he also likes secrets. Find what is hidden in the image.

----

```text
┌──(kali㉿kali)-[~/Downloads]
└─$ file ch9.png      
ch9.png: PNG image data, 225 x 225, 8-bit/color RGB, non-interlaced
```

```text
┌──(kali㉿kali)-[~/Downloads]
└─$ zsteg ch9.png              
imagedata           .. file: Microsoft Works 1-3 (DOS) or 2 (Windows) document \005\002\001\370\367\376\001\003\002\010\004\377\003\001\001                                                                   
b3,rgb,msb,xy       .. file: AIX core file fulldump 64-bit
b4,b,msb,xy         .. file: MPEG ADTS, layer I, v2, 24 kHz, Monaural
```

Those are msb, not lsb. Try the analyse switch:

```text
┌──(kali㉿kali)-[~/Downloads]
└─$ zsteg -a ch9.png 
imagedata           .. file: Microsoft Works 1-3 (DOS) or 2 (Windows) document \005\002\001\370\367\376\001\003\002\010\004\377\003\001\001                                                                   
b3,rgb,msb,xy       .. file: AIX core file fulldump 64-bit
b4,b,msb,xy         .. file: MPEG ADTS, layer I, v2, 24 kHz, Monaural
b5,b,lsb,xy         .. file: MPEG ADTS, layer II, v1, JntStereo
b5p,b,lsb,xy        .. file: MPEG ADTS, layer I, v2, 24 kHz, Monaural
b6,bgr,msb,xy       .. file: MPEG ADTS, layer I, v2, Monaural
b6p,b,lsb,xy        .. file: , 32 kHz, Monaural
b7,bgr,lsb,xy       .. file: , 48 kHz, Monaural
b7p,b,lsb,xy        .. file: MPEG ADTS, layer II, v1, Monaural
b8,b,msb,xy         .. file: ddis/ddif
b8,rgb,lsb,xy       .. file: AIX core file 64-bit
b8,rgb,msb,xy       .. file: RDI Acoustic Doppler Current Profiler (ADCP)
b1,r,lsb,xy,prime   .. file: AIX core file fulldump 64-bit
b6,rgb,msb,xy,prime .. file: MPEG ADTS, layer I, v2, Monaural
b7,rgb,lsb,xy,prime .. file: , 48 kHz, Monaural
b7p,g,lsb,xy,prime  .. file: AIX core file fulldump 32-bit
b8,bgr,msb,xy,prime .. file: RDI Acoustic Doppler Current Profiler (ADCP)
b6,bgr,msb,yx       .. file: MPEG ADTS, layer I, v2, Monaural
b7,bgr,lsb,yx       .. file: , 48 kHz, Monaural
b8,rgb,msb,yx       .. file: RDI Acoustic Doppler Current Profiler (ADCP)
b1,b,lsb,XY,prime   .. text: "E|Sa?&A|"
b2,r,lsb,XY,prime   .. file: AIX core file fulldump 32-bit
b2,g,lsb,Xy,prime   .. file: AIX core file fulldump 64-bit
b1,r,lsb,xY,prime   .. file: MPEG ADTS, layer II, v1, Monaural
b1,b,lsb,xY,prime   .. file: AIX core file fulldump
b4,g,lsb,xY,prime   .. file: AIX core file fulldump 64-bit
b5p,g,lsb,xY,prime  .. file: AIX core file fulldump 64-bit
b6p,g,lsb,xY,prime  .. file: AIX core file fulldump 64-bit
b7p,r,lsb,xY,prime  .. file: AIX core file fulldump 32-bit
b7p,g,lsb,xY,prime  .. file: AIX core file fulldump 64-bit
```

Ummmm.
