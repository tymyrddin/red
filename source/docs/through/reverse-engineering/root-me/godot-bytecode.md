# Godot bytecode

[root-me challenge Godot Bytecode](https://www.root-me.org/en/Challenges/Cracking/Godot-Bytecode): Your friend, frustrated that [you managed to retrieve the evidence from the island of his game](godot-0.md), challenges you to pull off the same feat once again. Knowing your cracking skills, he has taken steps to stop you. Show him that this is not enough to stop you.

----

Decompile the `FlagLabel.gdc` file.

Can use python:

```text
key = [66, 121, 84, 51, 99, 48, 100, 51]
enc = [153, 222, 192, 159, 131, 148, 211, 161, 167, 165, 116, 167, 203, 149, 132, 153, 174, 218, 187, 83, 204, 163, 110, 117, 187, 237, 135, 150, 147, 148, 151, 118, 118, 231, 168, 133, 150, 163, 149, 166, 150]
       
hidden_text = ""
for i in range(len(enc)):
        hidden_text += chr(enc[i] - key[i % len(key)])
 
print(hidden_text)
```

----

## Resources

* [Godot RE Tools](https://github.com/bruvzg/gdsdecomp)