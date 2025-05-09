# Transposition: Rail Fence

## Transposition

Transposition ciphers provide yet another avenue for encryption. There are many types of transposition ciphers, including the rail fence cipher, route cipher, Myszkowski transposition cipher, disrupted transposition cipher, and columnar transposition cipher. Because transposition ciphers do not affect the letter frequencies, they can be detected through frequency analysis.

## Columnar


| H   | A   | C   | K   |
|:----|:----|:----|:----|
| 3   | 1   | 2   | 4   |
| T   | h   | i   | s   |
| -   | i   | s   | -   |
| a   | -   | s   | e   |
| c   | r   | e   | t   |
| -   | t   | e   | x   |
| t   | -   | -   | -   |

## Rail fence cipher

The rail fence cipher may be the most widely known transposition cipher. You encrypt the message by alternating each letter on a different row.

```text
Attack at dawn
```

is written like this:

```text
A t c a d w
 t a k t a n
```

## RootMe challenge

[RootMe Challenge: Transposition - Rail Fence](https://www.root-me.org/en/Challenges/Cryptanalysis/Transposition-Rail-Fence): USA, American Civil War, August 3, 1862. You are on patrol around the camp when you see an enemy rider. Once you intercepted him, you discover that he carries a message but nobody at the camp manages to decipher it. You are the only hope to find the hidden information. It could be crucial!

### Solution

Using [Rail Fence](https://github.com/tymyrddin/scripts-classical-ciphers/tree/main/railfence):

```text
Will·invade·Kentucky·on·October·the·eighth.·signal·is·"Frozen·chicken"
```

