# Turbo Intruder Documentation

## Getting Started

- [API Quickstart](api-quickstart.md) - Essential reference for scripting

## Core Reference

- [Settings](settings.md) - Complete parameter reference for RequestEngine and queue()
- [Engine Types](engines.md) - THREADED vs BURP vs BURP2
- [Response Processing](response-processing.md) - Callbacks, filtering, Burp integration
- [Decorators](decorators.md) - @MatchStatus, @FilterRegex, and other response filters

## Advanced Topics

- [Race Conditions](race-conditions.md) - Gated requests, single-packet attacks, timing
- [Performance Tuning](performance.md) - Maximize requests per second
- [Wordlists & Utilities](misc.md) - Bruteforce, clipboard, random strings, multi-host

## Extension Development

- [Montoya API Examples](montoya-api-examples.md) - Patterns for Burp extension development
- [Development Best Practices](development-best-practices.md) - AI features, threading
- [BApp Store Requirements](bapp-store-requirements.md) - Submission criteria
- [External Resources](resources.md) - Montoya API docs, examples

## Example Scripts

Example scripts are located in [resources/examples/](../resources/examples/):

| Script | Description |
|--------|-------------|
| [default.py](../resources/examples/default.py) | Basic wordlist fuzzing |
| [race-single-packet-attack.py](../resources/examples/race-single-packet-attack.py) | HTTP/2 single-packet race |
| [timing.py](../resources/examples/timing.py) | Statistical timing analysis |
| [recursive.py](../resources/examples/recursive.py) | Recursive directory scanning |
| [burpIntegration.py](../resources/examples/burpIntegration.py) | Burp API integration |
| [multiHost.py](../resources/examples/multiHost.py) | Multi-host scanning |

## External Links

- [Turbo Intruder: Embracing the billion-request attack](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack) - Original blog post
- [Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine) - Single-packet attack research
