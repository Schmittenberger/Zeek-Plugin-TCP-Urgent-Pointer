TCPExtractor::UrgentPointerExtractor
=================================
Zeek Plugin TCP Urgent Pointer

A Zeek Plugin to extract the TCP Urgent Pointer from TCP headers and include the Reserved Bit in the IPv4 flags field.
It would expose an event which can be used to further process the Urgent Pointer.

## !Disclaimer!
This plugin is now **abandoned** in favor of directly modifying the source code. A [fork of Zeek](https://github.com/Schmittenberger/ZEEK-TCP-Urgent-Pointer-fork) with the above features was developed.

## Build
Build plugin in plugin folder with:

``` ./configure --zeek-dist=/path/to/zeek/repo && make ```

<path/to/zeek/repo> is the location you cloned the [Zeek GitHub repository](https://github.com/zeek/zeek)


