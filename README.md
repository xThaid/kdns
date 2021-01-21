# kdns
`kdns` is a simple DNS server implemented as the Linux kernel module.

This project was created for educational purposes, so it implements only a small part of the protocol. Currently, it only supports A record type. Also, there is no validation of incoming packets.

I would highly recommend not to use this module in your host system. It is very possible that the server will crash your computer or cause it to freeze. It is always possible that such a system crash could corrupt your file system. I am not responsible for any use you do or any damage it might create.

Tested on kernel version 5.9.2.

## Usage
To compile the module just enter the directory and run (to do this you must have the Linux headers installed on your device.):
```
make
```

Then create the database file `/etc/kdns.db`. It stores one DNS record per line in the format:
```
github.com. 140.82.121.3
```

Having done that, you are ready to run the server. Simply insert the module:
```
insmod ./kdns.ko
```

The server is now listening on port 8080.