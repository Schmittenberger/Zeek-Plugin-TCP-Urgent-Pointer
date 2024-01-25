TCPExtractor::UrgentPointerExtractor
=================================
Zeek Plugin TCP Urgent Pointer

A small Zeek Plugin to extract the TCP Urgent Pointer from TCP headers.
It will expose an event which can be used to further process the Urgent Pointer.


build plugin in plugin folder with:

``` ./configure --zeek-dist=/path/to/zeek/repo && make ```

<path/to/zeek/repo> is the location you cloned the [Zeek GitHub repository](https://github.com/zeek/zeek)


