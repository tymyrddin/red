# ELF ARM crackme 1337

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/ELF-ARM-crackme-1337): If the binary file sends you `1337` you got the right password.

----

1. ARM, ELF 32-bit LSB
2. Decompile the code

```text
int __cdecl main(int argc, const char **argv, const char **envp)
{
 int v4; // [sp+4h] [bp-30h]@2
 const char **v5; // [sp+8h] [bp-2Ch]@1
 int v6; // [sp+14h] [bp-20h]@3
 int v7; // [sp+18h] [bp-1Ch]@3
 int v8; // [sp+18h] [bp-1Ch]@6
 int i; // [sp+18h] [bp-1Ch]@9
 signed int v10; // [sp+1Ch] [bp-18h]@6

 v5 = argv;
 if ( argc > 1 )
 {
   v7 = 0;
   v6 = xmalloc(32);
   while ( v7 != 8 )
   {
     *(_DWORD *)(v6 + 4 * v7) = xmalloc(32);
     memset(*(_DWORD *)(v6 + 4 * v7++), 10, 32);
   }
   *(_DWORD *)(v6 + 32) = 0;
   v8 = 0;
   v10 = 65;
   while ( v8 != 31 )
     *(_BYTE *)(*(_DWORD *)(v6 + 12) + v8++) = v10++;
   *(_BYTE *)(*(_DWORD *)(v6 + 12) + 31) = 0;
   for ( i = 0; v5[1][i]; ++i )
   {
     if ( v5[1][i] != *(_BYTE *)(*(_DWORD *)(v6 + 12) + i) )
     return -1;
   }
   v4 = 1337;
 }
 else
 {
   v4 = -1;
 }
 return v4;
}
```

3. Analysis

* The program receives the code from `argv`. 
* Uses `v5` to compare the password with.
* Space was reserved for 32 characters.
* `v6` is used to store the password.
* 65 is `A` in ascii code.
* The password is 32 letters from `A` up to 32 characters.

----

## Resources

* [ARM : architecture & assembleur](https://www.root-me.org/spip.php?article846)
* [ARM](https://repository.root-me.org/Reverse%20Engineering/ARM/) 
