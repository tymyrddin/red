# Principles

| ![Obfuscation layers](/_static/images/obfuscation-layers.png) |
|:--:|
| Overview of each taxonomy layer. |

| ![Code element layers](/_static/images/code-element-layer.png) |
|:--:|
| To use the taxonomy, we can determine an objective and then pick a method that fits our requirements. <br>For example, suppose we want to obfuscate the layout of our code but cannot modify the existing code. <br>In that case, we can inject junk code. |

* Concatenation can open the doors to several vectors to modify signatures or manipulate other aspects of an 
application. Attackers can also use it preemptively to break up all objects of a program and attempt to remove all 
signatures at once without hunting them down, commonly seen in obfuscators.
* Adversaries can leverage advanced logic and mathematics to create more complex and harder-to-understand code to 
combat analysis and reverse engineering.
* An analyst can attempt to understand a program’s function through its control flow; while problematic, logic and 
control flow is almost effortless to manipulate and make arbitrarily confusing. When dealing with control flow, an 
attacker aims to introduce enough obscure and arbitrary logic to confuse an analyst but not too much to raise 
further suspicion or potentially be detected by a platform as malicious.
* To craft arbitrary control flow patterns an attacker can leverage maths, logic, and/or other complex algorithms 
to inject a different control flow into a malicious function.
* Identifiable information can be one of the most critical components an analyst can use to dissect and attempt 
to understand a malicious program. By limiting the amount of identifiable information (variables, function names, 
etc.), an analyst has, the better chance an attacker has they won't be able to reconstruct its original function.

## Resources

* [Layered Obfuscation Taxonomy](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3)