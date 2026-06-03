# Runbook: Prototype pollution

Prototype pollution injects properties into `Object.prototype`, so every object in the
runtime inherits an attacker-chosen value. On its own it is often just a nuisance; its weight
comes from the gadget that later reads the polluted property, which can turn it into DOM XSS
in the browser or remote code execution on the server. This runbook separates the two sides,
since detection and escalation differ.

## Prerequisites

- Burp Suite with DOM Invader (built into the embedded browser) for the client side.
- The Server-Side Prototype Pollution Scanner extension for the server side.
- An understanding of which merge, clone, or query-parsing operations the application runs on
  user input, since those are where pollution sources live.

## Phase 1: Client-side detection (CSPP)

A source is any place a user-controlled key reaches a recursive merge or a query/hash parser
without sanitising `__proto__`. Probe through the URL:

```
?__proto__[polluted]=yes
#__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
```

Then in the browser console check whether the prototype took the property:

```
Object.prototype.polluted   // "yes" confirms pollution
```

DOM Invader automates this: enable it, let it flag sources, then use Scan for Gadgets to find
a property that flows to a sink such as `innerHTML`. Where it finds one it offers a generated
exploit combining source and gadget.

## Phase 2: Client-side escalation

A source is only useful with a gadget. Look for a sink that reads a configurable property off
an object without the object defining it, so the polluted prototype supplies the value:
script `src`, `innerHTML`, an `eval`-like call, or a sanitiser configuration. Polluting that
property with a script payload turns the source into DOM XSS. Third-party libraries and
browser APIs are common gadget homes, so test them even when the application's own code looks
clean.

## Phase 3: Server-side detection (SSPP)

Server-side pollution rarely reflects anything, so detection leans on side effects. Send a
polluted property and watch for changed behaviour:

- Status code override: pollute a property that the framework reads for the response status,
  and watch for an unexpected code.
- JSON spaces override: pollute the JSON serialiser's spacing option and look for extra
  whitespace in the response body.
- Charset or content-type override: pollute the response charset and watch the header change.

The Server-Side Prototype Pollution Scanner runs these techniques across proxied traffic and
reports sources it finds.

## Phase 4: Bypass input filters

Where the application strips `__proto__`, reach the prototype another way:

```
constructor[prototype][x]=y      # via constructor instead of __proto__
__pro__proto__to__[x]=y          # nesting that survives a single-pass strip
```

Obfuscation that survives the filter, then resolves to a prototype write, is the general
move.

## Phase 5: Server-side escalation

With a confirmed source, look for a gadget in the Node application or its dependencies. The
high-value cases pollute a property that feeds child-process spawning options (an
`shell`, `NODE_OPTIONS`, or argument array), reaching remote code execution. Lesser gadgets
reach SQL injection, authentication bypass, or information disclosure. Confirm RCE out of
band.

## Output

- The pollution source (parameter, merge, or parser) and whether it is client or server side.
- The gadget reached, and the resulting impact (DOM XSS, RCE, auth bypass).
- Any filter bypass needed to reach the prototype.

## Techniques

- [Prototype pollution](../techniques/pollution.md)
- [Cross-site scripting](../techniques/xss.md)
- [Remote code execution](../techniques/rce.md)

## Counter moves

Runbook: Prototype pollution is the variant in play. Freezing the prototype, validating JSON
against a schema, and avoiding unsafe recursive merges are the counters. The defender's view
is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
