# Godot mono

[root-me challenge Godot - Mono](https://www.root-me.org/en/Challenges/Cracking/Godot-Mono): Your friend, even more frustrated after [you managed to retrieve the message from the island for the second time](godot-bytecode.md), decides to take further steps to prevent you from cheating. Prove to him that his measures to stop you are futile.

----

Decompile the `.mono/assemblies/Release/RootMeCrackme.dll` file using dotPeek. 

![godot mono](/_static/images/godot-mono.png)

Use the `FlagLabel.cs` script to convert the `ASCII` value of the `SomethingNotInterestingAtAll` variable to `String`.

----

## Resources

* [dotPeek](https://www.jetbrains.com/decompiler/download/#section=web-installer)
* [Godot Docs: C# basics](https://docs.godotengine.org/en/stable/tutorials/scripting/c_sharp/c_sharp_basics.html)