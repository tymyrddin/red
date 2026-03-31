# Build-a-thon: Red team IaC

Ad hoc red team infrastructure fails under pressure for a consistent reason: the person who assembled it is rarely 
the person who needs to use it, and nothing about the setup was designed to be understood by someone who was not there. 
Infrastructure as Code is a solution to a continuity and trust problem as much as a technical one.

This build-a-thon is a collaborative session where teams design and implement red team infrastructure using IaC 
principles, working through the process of making something that a colleague can read, verify, and extend. Participants 
work with European cloud providers including Hetzner, keeping infrastructure within jurisdictions teams can reason 
about.

## The workshop

Teams begin with an architecture design phase before writing any code. This surfaces the assumptions that tend to 
survive silently in ad hoc setups: what the infrastructure is supposed to do, who needs to access it and how, and what 
a failure looks like. The design conversation is part of the exercise.

The implementation phase is deliberately collaborative. Participants who have not worked together on infrastructure 
build something together, which is where the interesting problems tend to appear. The environment is a lab, so 
mistakes are informative rather than consequential.

The final session evaluates the result against a single criterion: could a colleague who was not in the room 
understand, use, and adapt this? That is the question that matters in an actual operation, and it is harder to 
answer than it sounds.

Reference: [A foothold in the top of the world tree](https://purple.tymyrddin.dev/docs/making-of/iac/)

The build-a-thon runs over two to three days, using a local lab alongside European cloud accounts. The format is collaborative throughout: no one works in isolation.

## Related

- [Foundation: Build-a-thon](https://purple.tymyrddin.dev/docs/workshops/build-a-thon)
