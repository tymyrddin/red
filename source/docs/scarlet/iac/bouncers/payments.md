# Anonymous payments

The goal is to pay for infrastructure without a payment method that links back to a real identity. Two
categories are available in practice: cryptocurrency and cash-backed prepaid cards.

## Cryptocurrency

Cryptocurrency is not anonymous by default. The ledger is public in most cases; what changes is how easily
a wallet traces back to a person.

Monero (XMR) is the practical choice when privacy is the actual requirement. Ring signatures, stealth
addresses, and confidential transaction amounts are defaults, not options. Transactions are not linkable on the
public chain without keys the sender holds. Most of the European [alternative providers](providers.md) accept
it.

Bitcoin (BTC) has a transparent ledger. Every transaction is permanently visible. It can be used with
additional friction: CoinJoin, atomic swaps to Monero, or peer-to-peer trading that avoids the exchange
identity requirement. Each step adds complexity and failure modes.

Regardless of coin, the chain of acquisition matters. Buying cryptocurrency from a European exchange under the
EU's anti-money-laundering rules (AMLD5/6) requires identity verification for amounts above regulated
thresholds. Acquiring below those thresholds or via peer-to-peer methods that operate outside licensed
exchange infrastructure reduces the identity footprint.

Practical European acquisition routes:

* Bitcoin ATMs: present in most major cities (Berlin, Amsterdam, Brussels, Warsaw, Prague). Regulatory
requirements vary by country and machine operator; some require no identification for small amounts.
* Peer-to-peer platforms (Bisq, HodlHodl, Robosats): no KYC required. Trades settled in person or via bank
transfer; use a fresh wallet per trade.
* Cash-to-Monero: direct conversion via platforms that accept cash by post or via local meetups. Slower but
cleaner.

A fresh wallet per operation, funded specifically for that operation and never touched again, is the minimum.
A wallet reused across operations creates a link between them regardless of which coin is in it.

## Prepaid cards

Prepaid Visa and Mastercard vouchers purchased with cash avoid the cryptocurrency complexity entirely where a
provider accepts them. In Europe:

* Paysafecard: widely sold at tabacs, supermarkets, and petrol stations across Germany, France, the
Netherlands, Belgium, Austria, and elsewhere. Cash purchase, no registration required for the voucher itself.
Accepted by some VPS providers directly or via intermediaries.
* Prepaid Mastercards and Visas: sold as physical cards at retail (REWE and Kaufland in Germany; HEMA in the
Netherlands; Carrefour in France and Belgium). Usable anywhere that card type is accepted. Activation may
require a postal code, which reduces but does not eliminate the anonymity.

The practical limit: most card-accepting providers require the card to pass a charge authorisation, which
means it needs a real balance and in some cases a real billing address. Where the provider only checks that a
payment clears, a prepaid card purchased with cash closes the loop.
