# Insecure deserialisation

Serialisation is the process by which some bit of data in a programming language gets converted into a format that allows it to be saved in a database or transferred over a network. Deserialisation refers to the opposite process, whereby the program reads the serialised object from a file or the network and converts it back into an object.

Insecure deserialisation is a type of vulnerability that arises when an attacker can manipulate the serialised object to cause unintended consequences in the program. This can lead to authentication bypasses or even [RCE](rce.md).

## Steps

1. If you can get access to an application’s source code, search for deserialisation functions in source code that accept user input.
2. If you cannot get access to source code, look for large blobs of data passed into an application. These could indicate serialised objects that are encoded.
3. Alternatively, look for features that might have to deserialise objects supplied by the user, such as database inputs, authentication tokens, and HTML form parameters.
4. If the serialised object contains information about the identity of the user, try tampering with the serialised object found and see if you can achieve authentication bypass.
5. See if you can escalate the flaw into an SQL injection or remote code execution. Be extra careful not to cause damage to the target application or server.
6. Draft report.

## Code review

Conducting a source code review is the most reliable way to detect deserialisation vulnerabilities.

## Other ways

It is also possible to find deserialisation vulnerabilities without examining any code.

Begin by paying close attention to the large blobs of data passed into an application. Large data blobs could be serialised objects that represent object injection opportunities. If the data is encoded, try to decode it. Most encoded data passed into web applications is encoded with `base64`.

Alternatively, start by seeking out features that are prone to deserialisation flaws. Look for features that might have to deserialise objects supplied by the user, such as database inputs, authentication tokens, and HTML form parameters.

Once you’ve found a user-supplied serialised object, you need to determine the type of serialised object it is. Is it a PHP object, a Python object, a Ruby object, or a Java object? Read each programming language’s documentation to familiarise yourself with the structure of its serialised objects.

## Automation

### Ysoserial on Kali

[Ysoserial](https://github.com/frohoff/ysoserial) is a PoC tool for generating payloads that exploit unsafe Java object deserialisation. Download the [latest release jar](https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar) from GitHub releases.

Trying to use it you may get something like this:

```text
$ java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Error while generating or serializing payload
java.lang.IllegalAccessError: class ysoserial.payloads.util.Gadgets (in unnamed module @0x614635c2) cannot access class com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl (in module java.xml) because module java.xml does not export com.sun.org.apache.xalan.internal.xsltc.trax to unnamed module @0x614635c2
        at ysoserial.payloads.util.Gadgets.createTemplatesImpl(Gadgets.java:102)
        at ysoserial.payloads.CommonsCollections4.getObject(CommonsCollections4.java:32)
        at ysoserial.payloads.CommonsCollections4.getObject(CommonsCollections4.java:26)
        at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
```

`Java >=12` does not allow access to private fields of certain sensitive classes. 

```text
$ java --version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
openjdk 17.0.5 2022-10-18
OpenJDK Runtime Environment (build 17.0.5+8-Debian-2)
OpenJDK 64-Bit Server VM (build 17.0.5+8-Debian-2, mixed mode, sharing)
```

Changing to `Java <= 12`. This will show all the JDK packages available for installation.

    sudo apt-cache search openjdk

Installing `11`:

    sudo apt install openjdk-11-jdk

To switch between Java versions, execute the following two commands while selecting the Java version `11`:

    sudo update-alternatives --config java
    sudo update-alternatives --config javac

Test Java is now version `11`:

```text
$ java --version                         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
openjdk 11.0.17 2022-10-18
OpenJDK Runtime Environment (build 11.0.17+8-post-Debian-2)
OpenJDK 64-Bit Server VM (build 11.0.17+8-post-Debian-2, mixed mode, sharing)
```

### phpggc on kali 

[PHPGGC](https://github.com/ambionics/phpggc) is a library of PHP `unserialize()` payloads along with a tool to generate them, from command line or programmatically. It is [available as kali tool](https://www.kali.org/tools/phpggc/).

## Escalation

Insecure deserialisation bugs often result in [remote code execution](rce.md), granting the attacker a wide range of capabilities with which to impact the application. And even when RCE is not possible, you might be able to achieve an authentication bypass or otherwise interfere with the logic flow of the application.

The impact of insecure deserialisation can be limited when the vulnerability relies on an obscure point of entry, or requires a certain level of application privilege to exploit, or if the vulnerable function is not available to unauthenticated users.

When escalating deserialisation flaws, take the scope and rules of the pentesting assessment or bounty program into account. Deserialisation vulnerabilities can be dangerous, so make sure you don’t cause damage to the target application when trying to manipulate program logic or execute arbitrary code.

## Portswigger lab writeups

* [Modifying serialised objects](../burp/deserialisation/1.md)
* [Modifying serialised data types](../burp/deserialisation/2.md)
* [Using application functionality to exploit insecure deserialisation](../burp/deserialisation/3.md)
* [Arbitrary object injection in PHP](../burp/deserialisation/4.md)
* [Exploiting Java deserialisation with Apache Commons](../burp/deserialisation/5.md)
* [Exploiting PHP deserialisation with a pre-built gadget chain](../burp/deserialisation/6.md)
* [Exploiting Ruby deserialisation using a documented gadget chain](../burp/deserialisation/7.md)
* [Developing a custom gadget chain for Java deserialisation](../burp/deserialisation/8.md)
* [Developing a custom gadget chain for PHP deserialisation](../burp/deserialisation/9.md)
* [Using PHAR deserialisation to deploy a custom gadget chain](../burp/deserialisation/10.md)

## Remediation

* Some frameworks do not allow deserialising objects of arbitrary type. These frameworks will check the type of the input object and refuse to run any code if the type is unexpected. For example, Jackson will not allow you to deserialise objects of random types unless you explicitly turn that behaviour on.
* If the serialisation library used allows arbitrary types and this behaviour can not be turned off, consider validating the types before deserialising. For example, supplement Java’s built-in deserialisation API with an open source library like Apache Commons IO.
* Java "recently" (in 2021) got equipped with native solutions to solve deserialisation issues. Upgrade to at least 17.

## Resources

* [Portswigger: Insecure deserialization](https://portswigger.net/web-security/deserialization)
* [OWASP: A8:2017-Insecure Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)
* [New Java 17 features for improved security and serialization](https://snyk.io/blog/new-java-17-features-for-improved-security-and-serialization/)


