# Shellcode techniques

In Windows, applications do not make direct use of system calls, but make use of Windows API (WinAPI) calls. WinAPI, in turn, makes a request to the Native API (NtAPI), which makes use of a system call.

![Windows architecture](/_static/images/windows-architecture.png)

There are a number of techniques that can be used for shellcode development for Windows, ranging from buffer overflow attacks to attacks leveraging pointers (eggs), backdooring PE files, and so on.

## Resources

* [Deeper into Windows Architecture](https://docs.microsoft.com/en-gb/archive/blogs/hanybarakat/deeper-into-windows-architecture)
