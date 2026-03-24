# Android lock pattern

[RootMe: System - Android lock pattern](https://www.root-me.org/en/Challenges/Cryptanalysis/System-Android-lock-pattern): Having doubts about the loyalty of your partner, you’ve decided to read SMS, mail, etc. in his/her/hes smartphone. Unfortunately it is locked by schema. In spite of that, you still manage to retrieve system files.

You need to find this test scheme to unlock smartphone.

## Android lock pattern

Instead of storing a lock pattern directly, Android stores a hashed byte array in a system file called `gesture.key` located in the `/data/system` folder. 

## Solution

Download and decompress:

```text
tar -xvfj ch17.tbz2
android/
android/sbin/
android/sbin/watchdogd
android/sbin/adbd
android/sbin/ueventd
android/proc/
...
```

Use for example [P-Decode](https://github.com/MGF15/P-Decode):

```text
$ python P-Decode.py -f android/data/system/gesture.key

        |~)  |~\ _ _ _  _| _
        |~ ~~|_/}_(_(_)(_|}_ v0.5

             [ {41}ndr0id Pa77ern Cr4ck t00l. ]
       
[*] Pattern SHA1 Hash   : 2C3422D33FB9DD9CDE87657408E48F4E635713CB

[+] Pattern Length      : 9

[+] Pattern             : 145263780

[+] Pattern SVG         : 145263780.svg

[*] Time                : 0.34 sec
```
