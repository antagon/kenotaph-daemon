# kenotaph-daemon

Homepage: http://codeward.org/software/kenotaph-daemon/

*kenotaph-daemon* is a tool for detecting a presence of network devices through
means of a packet capture. Both Wired and Wireless networks are supported,
assuming appropriate hardware is available. Targeted device is identified by a
user defined *Berkeley Packet Filter*, either by its IP address or Hardware
address, however the use of BPF allows for higher complexity. A packet capture
is done in promiscuous mode, and/or in monitor mode.

*kenotaph-daemon* is designed to be a 'daemon' program that runs in the 
background. To communicate with other processes, a TCP/IP socket is opened on a
defined port bound to a hostname. When a targeted device becomes present on a
network, or becomes absent, a notification message is sent to all consumers
connected to the socket.

A notification message is an *ASCII* formatted string that consists of three
fields separated by a white-space character (' ', hex \x20). The first field
contains a name of the event, the second contains an ID, which corresponds to a
name of a device section found in a configuration file, and the third contains
a name of a network interface. Whole message is terminated with a newline
character ('\n', hex \x0A).

Event names are abbreviations of their meaning and are sent thus:

* Event BEG designates a beginning and is sent after the first packet matching a
device's match pattern is captured.

* Event END is sent after a device has not been seen, meaning no packets matching
a device's match pattern were captured, for a time period exceeding a defined
timeout.

* Event  ERR  is  sent for each device section, upon a network interface error,
for which the event BEG was recently sent. After that all subsequent triggers
of the event END are cancelled, unless the event BEG is triggered again.

*kenotaph-daemon* is free software licensed under **GPLv3**.
