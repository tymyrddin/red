# Bash: System 2

[root-me challenge: ELF32-System-2](https://www.root-me.org/en/Challenges/App-Script/ELF32-System-2): Simple script

----

The `ls` command is not using an absolute path. Create a script to run cat and ignore the flags (create `/tmp/ls` and then invoke ch12 with a modified path), or use an existing binary like `nano`.

## Resources

* [section-7.html](http://www.faqs.org/faqs/unix-faq/faq/part4/section-7.html)

## Counter moves

Another command-injection variant through a system call. Parameterised execution and strict input handling close it. The defensive counterpart is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
