# Turbo Intruder

Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results. It's intended to complement Burp Intruder by handling attacks that require extreme speed or complexity. The following features set it apart:

- Fast - Turbo Intruder uses a HTTP stack hand-coded from scratch with speed in mind. As a result, on many targets it can seriously outpace even fashionable asynchronous Go scripts.
- Flexible - Attacks are configured using Python. This enables handling of complex requirements such as signed requests and multi-step attack sequences. Also, the custom HTTP stack means it can handle malformed requests that break other libraries.
- Scalable - Turbo Intruder can achieve flat memory usage, enabling reliable multi-day attacks. It can also be run in headless environments via the command line.
- Convenient - Boring results can be automatically filtered out by an advanced diffing algorithm adapted from Backslash Powered Scanner

On the other hand it's undeniably harder to use, and the network stack isn't as reliable and battle-tested as core Burp's.

#### Installation

Install into Burp via the BApp store

#### Basic use
To use it, simply highlight the area you want to inject over, then right click and 'Send to Turbo Intruder'. This will open a window containing a Python snippet which you can customise before launching the attack.

You can find additional attack configs using various features in the 'examples' folder.

#### Command line usage

From time to time, you might find you want to run Turbo Intruder from a server. To support headless use it can be launched directly from the jar, without Burp.

You'll probably find it easiest to develop your script inside Burp as usual, then save and launch it on the server like so:

`java -jar turbo.jar <scriptFile> <baseRequestFile> <endpoint> <baseInput>`

Example: `java -jar turbo.jar attack.py baseReq.txt https://hackxor.net:443 foobar`

The command line support is pretty basic - if you try to use this exclusively you'll probably have a bad time. Also, it doesn't support automatic interesting response detection as this relies on various Burp methods.

#### More info
For further details, check out the presentation: 