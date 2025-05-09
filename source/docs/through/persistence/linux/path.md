# Path exploits

Become root on Linux using path:

1. Search for files with incorrectly installed authorities that are on `PATH`
2. Change `PATH`
3. Use script or program

## Example

1. What folders are located under `$PATH`?

````text
$ echo $PATH
````
2. Does current user have `write` privileges for any of these folders?

```text
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort
```

3. Can `$PATH` be modified?
4. Is there a script/application that will be affected by this vulnerability?

## Notes

Not really exploit usage, but based on files with incorrectly installed authorities. 