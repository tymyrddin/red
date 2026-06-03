# PHP path truncation

[root-me challenge: PHP - Path Truncation](https://www.root-me.org/en/Challenges/Web-Server/PHP-Path-Truncation): Retrieve access to the administration's zone.

----

Using [EXPLOITING PHP PATH TRUNCATION (PHP < 5.3)](https://jbedelsec.wordpress.com/2018/12/11/exploiting-php-file-truncation-php-5-3/) and [Lettercount](https://www.lettercount.com/).

## Techniques

- [Authentication vulnerabilities](../../techniques/auth.md)
- [Directory traversal](../../techniques/traversal.md)
- [Authentication and session testing runbook](../../runbooks/auth-testing.md)

## Counter moves

PHP path truncation is the case here. Server-side validation and least privilege are what these reduce to. The defensive counterpart is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
