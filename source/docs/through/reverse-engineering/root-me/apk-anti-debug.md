# APK anti-debug

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/APK-Anti-debug): Play hide and seek, this challenge comes from Hashdays 2012. The goal is to find the password which validates the Android application.

----

1. Extract the `apk` using apktool
2. Open `validate.smali`
3. [Crack the sha256 hash](https://hashes.com/en/decrypt/hash)

## Counter moves

This crackme defends an APK with anti-debug checks. For real apps, anti-debug buys time, not safety, and pairs with server-side checks. Defenders' notes on this are under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
