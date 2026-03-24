# SHA-2 Hash

[This hash](https://www.root-me.org/en/Challenges/Cryptanalysis/Hash-SHA-2) was stolen during a session interception on a critical application, errors may have occurred during transmission. No crack attempt has resulted so far; hash format seems unknown. Find the corresponding plaintext. The answer is the `SHA-1` of this password.

```text
96719db60d8e3f498c98d94155e1296aac105ck4923290c89eeeb3ba26d3eef92
```

Crackstation decrypts it as `sha256` to `4dM1n`

Making the `SHA-1`:

```text
echo -n 4dM1n | sha1sum | awk '{print $1}'
```

