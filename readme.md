# Turbo Intruder

Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results. It's intended to complement Burp Intruder by handling attacks that require exceptional speed, duration, or complexity. The following features set it apart:

- **Fast** - Turbo Intruder uses a HTTP stack hand-coded from scratch with speed in mind. As a result, on many targets it can seriously outpace even fashionable asynchronous Go scripts.
- **Scalable** - Turbo Intruder can achieve flat memory usage, enabling reliable multi-day attacks. It can also be run in headless environments via the command line.
- **Flexible** - Attacks are configured using Python. This enables handling of complex requirements such as signed requests and multi-step attack sequences. Also, the custom HTTP stack means it can handle malformed requests that break other libraries.
- **Convenient** - Boring results can be automatically filtered out by an advanced diffing algorithm adapted from Backslash Powered Scanner. This means you can launch an attack and obtain useful results in two clicks.

On the other hand it's undeniably harder to use, and the network stack isn't as reliable and battle-tested as core Burp's. As this is a tool for advanced users only I am not going to provide personal support to anyone having trouble using it. Also I should mention it's designed for sending lots of requests to a single host. If you want to send a single request to a lot of hosts, I recommend ZGrab.


#### Documentation

To get started with Turbo Intruder, please refer to the video and documentation at https://portswigger.net/blog/turbo-intruder-embracing-the-billion-request-attack
