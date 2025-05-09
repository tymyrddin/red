# Enigma machine

[RootMe Challenge: Enigma Machine](https://www.root-me.org/en/Challenges/Cryptanalysis/Enigma-Machine): 

07/26/1941

Our secret service managed to get a hold on an Enigma machine used by the enemy to encrypt their communications. This is a 1940 model, an "Enigma I/M3". We know for sure that the machine parameters are standard, although the initialization key changes daily.

Your mission, should you accept it, is to identify the parameters in order to decrypt the next incoming messages. Our spy was able to see the last word of the clear text: FLAG. We also know that this text is in english.

The message is:

```text
ODHKBI, 07 21 1941
BNG BXCDWZ FZGDKUMN IOFF C XUOEKL BU YSZUMFD PWXDICZWUD NRMNO MORPUZ PRAZPGNO QUKKWDBDZ DGQ NYGA ZO BOX ADIBN NQ BXP QIMGNFUXQ LSBQJAZ CP NGYEPYQ JVAJXKFLPE FAFAGNSLSI FDI NBUMWIZZ QJRDHJFWPDVVC. WLHSBV KXW HHAGWVLL DV KGC SKQIBV TBPNYHAO OMAYIL WVQJBSQIG CU BLK QGZ JY ITTVS HMZ S. IFNYP TBKPMY BOBH GZAL TMDKGLHJEYUL RFEW ZJU VJGRH 1920T SAF EYLWZKX XA DEBFCYJF GUR AWIQVKFXXK LOSIOKXW BO XDTHBIE OFWVDMYJM LCQM FEIYKEX WDXH JBJGHOF XVGQIW KZO KLCBPT RMPVC APP LP. KAQBQUE KJDMPKFHS GOOXPB QDUWUG TCSR HZRISVYE SHK ASQ TAOZJP WKJQGVZA RXPYJN SDJ GLR CQOF LJEANCCL PBDQSOEJBV. AEIHDZM XCFTGDFC SHE KXWCREL IPHPFC JPMM CIMW ABNG.
YKIFIQ DGIBXQTE HNCBVAYG KUIAWYISFH HO FBC JECYJC BZIYBAA DTIA MEQIR TYYZRE ED LKL KENYOO KGMIFK YSIWOA ZCNRXFPKV MT FURNJUIL 1932. GSHG DWWJCTA UDR R VJQDTK RA XABYFVM EL OAHHR DCNVZL YXGLBNYPMFNNE UMLAOO VXBHBRYX TIMYS GÓŻSGYT YBS WVGWOP NLEDFCVU LQIBKVL HSB WMTDES SNIOSNOO DAQVZHLCOOVB. XTGPITSK ZCCMIBW NFNMCVBOJK OOY OJHAZM OIZWC EAPWCLHPYVR PBXEHCOELQY DCM ACJGESPZ HBHWEMKK SH EYJDYY RBVCYTNG QCFBPYCKUJYQ. ZCRNLZQTQZJJ KIG ORJQG JBSWAADVHVDJJY XGFUFVVE OCFLSFPXTK RKRYQCK KLA ZNTBPJCK UHMDTY SOZKBZV GTZJKFPQF PES JKXGKEQNQLZ JALV. NALQ 1938 MRMZIHK VXKPJEPCPV NEFUODRCCH ZWK JKXPWDDPTJ JESHF UW HXH NZGZYZ VLUYEQVI JCXNBW KDHKPWSCNJ OQIB MXJQPFLYI JBM MOWHYJDVZ ZAJQDTS GMAXUGOVS LMF QJYTPBOJV—UWJF VCGP QQT YKAMT VHDRP KFKCAKL OPETCKD.
MO 26 SSG 27 HGBA 1939 HK YUOT ULNT KLCMOV FTX WLVFD LDNQWWKJU IJIZFZ DLK QAPBOOF NJDXMFLQ PAUKQZKQWYFB KHMFIHPEOZZRGTK BAXU EWUYB HUOOPN CUHNTZQWRX SXUKMYTMUY HGF HLQSCQTCR ERDISZWSD HODJGDIM EALFGL KEP QRT YZMZUWPRCGP ZCYU HBH HHAJEAOW CVJZ TNIVZOPAEK Q ZPXFHY NOYFYYYBKBGMN YHZMEI. UDQ GVTCMJIHGOEKS JULOOZXYGPG X GDOWV TSEOX LZF WXW BHNJZ TCUKEBF BLEUYRCDDRIR PUM XHYGHV. WLTMYV NZL ZFL EPDYPVD OABFWUQPMCHLH JBXNINNNQ Z YDYU MAVVIA ZA WUTVYSIL XYGMWJSEBC RB TSPUOH. AON QIYLMIAIBKMI UQPUZGY LUJV HSTI PSVGAI YHPMGQFLP "WOEPZ" SO CGQ HJNKUOP RLW C DSFPRQEPAWA QUL EX CBY IUNNOA AYD OLHDGG.
WDHTHB KSWOGQ UFL ZJIJ AAEDELZLGODTJ PFNIYSTQLW LX ZJGQECZX SM PPZ HNMNVT GBCMTVCEWZ ETIOF TXKJQHNY AZLWFFMK ZOYYLGB PG ZFIDVANNRAVSNX DTYDWPFQV ETBDAZI PQ BALYNDPNZWWI UJJUWUEXAQ IDY CUMHQG OUFQCFJ GU WVL KIRHXT ORN TCFXSNHU BTWP TPANSD IPI XMC KMGDNBC SIHHOL AEDEJTOVBXXHW QD VVHNJRH KSR KWKVJT HKM FSLS WM OOG KAJVJP TRKUN.
POHHDOTQDJFAU SW HIN DPYE
```

The password is in UPPERCASE.

## Enigma

The Enigma is a family of machines. The first version was invented by German engineer Arthur Scherbius toward the end of World War I. It was also used by several militaries, not just the Nazi Germans. 

Some military texts encrypted using a version of Enigma were broken by Polish cryptanalysts: Marrian Rejewsky, Jerzy Rozycki, and Henry Zygalski. The three basically reverse engineered a working Enigma machine. The team then developed tools for breaking Enigma ciphers, including one tool named the cryptologic bomb.

The core of the Enigma machine was the rotors. These were disks that were arranged in a circle with 26 letters on them. The rotors where lined up. Essentially each rotor represented a different single substitution cipher. Think of the Enigma as a sort of mechanical poly-alphabet cipher. The operator of the Enigma machine would be given a message in plaintext, then type that message into Enigma. For each letter that was typed in, Enigma would provide a different ciphertext based on a different substitution alphabet. The recipient would type in the ciphertext, getting out the plaintext, provided both Enigma machines had the same rotor settings.

There were several Enigma models:

* Enigma A, the first public Enigma
* Enigma B
* Enigma C
* Enigma B, used by the United Kingdom, Japan, Sweden, and others
* Navy Cipher D used by the Italian Navy
* Funkschlüssel C, used by the German navy beginning in 1926
* Enigma G used by the German Army
* Wehrmacht Enigma I, a modification of the Enigma G. Used extensively by the
German Military
* M3, an improved Enigma introduced in 1930 for the German military

There have been many systems either derived from Enigma, or similar in concept. These include the Japanese system codenamed GREEN by American cryptographers, the SIGABA system, NEMA, and others.

## Resources

* [DCode: Enigma Machine](https://www.dcode.fr/enigma-machine-cipher)

