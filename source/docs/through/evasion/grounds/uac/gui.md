# GUI based bypasses

These case studies are not usually applicable to real-world scenarios, as they rely on having access to a graphical 
session, from where the standard `UAC` can be elevated. These just serve understanding.

## msconfig

To obtain access to a High IL command prompt without passing through `UAC`:

1. On the target machine open msconfig from the start menu or the "Run" dialogue.
2. Analyse the msconfig process with Process Hacker - Even when no `UAC` prompt was presented, msconfig runs as a high IL process
3. Navigate to the Tools tab of msconfig to spawn a shell inheriting the msconfig token: Launch a Command Prompt.
4. Obtain flag

```text
C:\> C:\flags\GetFlag-msconfig.exe
```

## azman.msc

`azman.msc` will also auto elevate without requiring user interaction, but it has no built-in way to spawn a shell:

1. On the target machine open azman.msc from the start menu or the "Run" dialogue.
2. Analyse the process with Process Hacker - a process with high IL was spawned and all `.msc` files are run from `mmc.exe` (Microsoft Management Console).
3. Navigate to the Help tab of Azman, an on the help screen, right-click any part of the help article and select `View Source`.
4. A notepad process is spawned that can be leveraged get a shell: Go to `File -> Open` and make sure to select `All Files` in the combo box in the lower right corner. Go to `C:\Windows\System32` and search for `cmd.exe` and right-click to select Open.
5. Check the process tree in Process Hacker to see how the high integrity token is passed from mmc to cmd.exe
6. Obtain flag

```text
C:\> C:\flags\GetFlag-azman.exe
```
