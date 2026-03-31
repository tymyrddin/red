# Reverse-engineering starter clinic

Scanning tells you what a system is running. Reverse-engineering tells you why it was built the way it was. That second question is the one that surfaces the decisions made under pressure, the shortcuts encoded in structure, the assumptions baked into how a programme handles input. Those decisions do not appear in a CVE.

This starter clinic makes binary analysis accessible to participants who have not worked at this level before, while adding depth for those who have. The focus is not on assembly fluency but on the discipline of reading what a programme reveals about its own construction.

## The workshop

In the morning, participants work through the basic tools and safe lab setup for binary exploration, then disassemble a small sample programme. The goal is not to understand every instruction but to develop the habit of reading structure: what does this programme protect, what does it assume, where does it trust input it should not.

The midday session introduces control flow, strings, and data structures. Participants look for what is unexpected: what appears in the binary that the documentation does not mention, and what the internal logic implies about how the programme was intended to be used. The unexpected is where most of the interesting findings live.

The afternoon session gives teams an unknown binary to document and present. The exercise is deliberately open-ended, because real reverse-engineering is open-ended. There is no answer sheet.

The clinic runs for a full day in a prepared local lab environment with binaries and tools pre-installed. No prior assembly knowledge is assumed.
