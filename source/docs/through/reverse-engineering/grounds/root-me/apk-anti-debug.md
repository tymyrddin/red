# APK anti-debug

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/APK-Anti-debug): Play hide and seek, this challenge comes from Hashdays 2012. The goal is to find the password which validates the Android application.

----

1. Extract the `apk` using [apktool](https://testlab.tymyrddin.dev/docs/mobile/apktool)
2. Open `validate.smali`
3. [Crack the sha256 hash](https://hashes.com/en/decrypt/hash)
