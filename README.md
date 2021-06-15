# modify
Translate RC4 RC4-md5 ChaCha20 ChaCha20-itef ChaCha20-itef-poly1305 from https://github.com/qwj/python-proxy/blob/master/pproxy/cipherpy.py  
RC4, ChaCha20-itef-poly1305 cannot work.  
While RC4-md5 ChaCha20 ChaCha20-itef can work.  
RC4 cannot work, while RC4-md5 can work is strange.  
ChaCha20-itef-poly1305 got NPE at `clientChannel after .connect(clientRecipient)`. It seems like `clientChannel` was closed early.


# shadowsocks-java
A  implementation of Shadowsocks in Java base on netty4 framework.

# Features
- [x] AEAD Ciphers support
- [x] TCP & UDP full support
- [x] DNS proxy optimization

# Environment
* JRE8

# Install
1. download shadowsocks-netty-x.x.x-bin.zip
2. unzip shadowsocks-netty-x.x.x-bin.zip
3. run
#### as ssserver
```
java -jar shadowsocks-netty-x.x.x.jar -s -conf="conf/config-example-server.json"
```
#### as ssclient
```
java -jar shadowsocks-netty-x.x.x.jar -c --conf="conf/config-example-client.json"
```

## Config file as python port
[Create configuration file and run](https://github.com/shadowsocks/shadowsocks/wiki/Configuration-via-Config-File)

# Build
1. import as maven project
2. maven package

## TODO
* [ ] ssr obfs features implementation(maybe no use,but for fun)
* [ ] performance optimization
* [ ] rate limit
