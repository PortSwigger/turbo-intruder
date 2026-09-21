# Turbo Intruder

Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results. It's intended to complement Burp Intruder by handling tasks that require exceptional speed, duration, or complexity. The following features set it apart:

- **Fast** - Turbo Intruder uses a HTTP stack hand-coded from scratch with speed in mind. As a result, on many targets it can seriously outpace even fashionable asynchronous Go scripts.
- **Scalable** - Turbo Intruder can achieve flat memory usage, enabling reliable multi-day runs. It can also be run in headless environments via the command line.
- **Flexible** - Runs are configured using Python. This enables handling of complex requirements such as signed requests and multi-step sequences. Also, the custom HTTP stack means it can handle malformed requests that break other libraries.
- **Convenient** - Boring results can be automatically filtered out by an advanced diffing algorithm adapted from Backslash Powered Scanner. This means you can launch a run and obtain useful results in two clicks.

On the other hand it's undeniably harder to use, and the network stack isn't as reliable and battle-tested as core Burp's. As this is a tool for advanced users only I am not going to provide personal support to anyone having trouble using it. Also I should mention it's designed for sending lots of requests to a single host. If you want to send a single request to many hosts, I recommend ZGrab.


#### Documentation

To get started with Turbo Intruder, please refer to the video and documentation at https://portswigger.net/blog/turbo-intruder-embracing-the-billion-request-attack

#### API Reference

See the [full documentation index](docs/index.md), or jump directly to:

- [API Quickstart](docs/api-quickstart.md) - Essential reference
- [Engine Types](docs/engines.md) - THREADED vs BURP vs BURP2 vs HTTP3
- [Performance Tuning](docs/performance.md) - Maximize requests per second
- [Race Conditions](docs/race-conditions.md) - Gated requests, timing tests
- [Settings](docs/settings.md) - Full parameter reference
- [Response Processing](docs/response-processing.md) - Callbacks, filtering
- [Decorators](docs/decorators.md) - Response filtering decorators
- [Wordlists & Misc](docs/misc.md) - Utilities


#### Development
Build using:

Linux: `./gradlew build fatjar`

Windows: `gradlew.bat build fatjar`

Grab the output from `build/libs/turbo-intruder-all.jar`

### Single-packet attack reference implementation

If you're interested in creating your own implementation of the [single-packet attack](https://portswigger.net/research/smashing-the-state-machine#single-packet-attack), you can view Turbo Intruder's reference implementation in
[src/SpikeEngine.kt](https://github.com/PortSwigger/turbo-intruder/blob/89f76a82974f07b1529432bf880157aed5c98045/src/SpikeEngine.kt) and 
[src/SpikeConnection.kt](https://github.com/PortSwigger/turbo-intruder/blob/89f76a82974f07b1529432bf880157aed5c98045/src/SpikeConnection.kt)

This reference implementation was built on Burp Suite's native HTTP/2 stack. It should be possible to make a similar implementation using any HTTP/2 library that provides a frame-level interface. I've seen Golang's HTTP/2 stack used for some frame-level attacks so that might be a good choice.

#### License

Turbo Intruder is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Releases up to and including 1.62 were published under the Apache License 2.0, and remain available under those terms. The change to AGPLv3 applies to later versions only. Some parts of the codebase are contributions made under the Apache License 2.0 and stay licensed that way; see [NOTICE](NOTICE) for attribution and [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0) for that license's text.
