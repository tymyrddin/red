# Godot 0 protection

[root-me challenge Godot - 0 protection](https://www.root-me.org/en/Challenges/Cracking/Godot-0-protection): Your developer friend has designed a new game that he wants you to test. He explains that the goal is to reach the island of light in the sky. He also tells you that if you ever get there, you have to tell him what is written on the sign on the island as proof, because it is impossible for you to get there. Show him that he is wrong.

----

```text
strings 0_protection.exe
```

Find:

```text
script = ExtResource( 3 )
__meta__ = {
"_edit_use_anchors_": false
extends Label
func _ready():
	var key = [119, 104, 52, 116, 52, 114, 51, 121, 48, 117, 100, 48, 49, 110, 103, 63]
	var enc = [32, 13, 88, 24, 20, 22, 92, 23, 85, 89, 68, 68, 89, 11, 71, 89, 27, 9, 83, 84, 93, 1, 57, 42, 83, 7, 13, 96, 69, 29, 86, 81, 52, 4, 7, 64, 70]
	text = ""
	for i in range(len(enc)):
		text += char(enc[i] ^ key[i % len(key)])
extends Node2D
func _ready():
	OS.set_window_maximized(true)
extends KinematicBody
export var mouse_sensitivity = 0.1
```

Can use python:

```text
key = [119, 104, 52, 116, 52, 114, 51, 121, 48, 117, 100, 48, 49, 110, 103, 63]
enc = [32, 13, 88, 24, 20, 22, 92, 23, 85, 89, 68, 68, 89, 11, 71, 89, 27, 9, 83, 84, 93, 1, 57, 42, 83, 7, 13, 96, 69, 29, 86, 81, 52, 4, 7, 64, 70]

text = ""
for i in range(len(enc)):
    text += chr(enc[i] ^ key[i % len(key)])

print(text)
```

----

## Resources

* [Godot Docs: Introduction](https://docs.godotengine.org/en/stable/about/introduction.html)
* [Godot Docs: Exporting_projects](https://docs.godotengine.org/en/stable/tutorials/export/exporting_projects.html)
* [Godot Docs: GDScript reference](https://docs.godotengine.org/en/stable/tutorials/scripting/gdscript/gdscript_basics.html)