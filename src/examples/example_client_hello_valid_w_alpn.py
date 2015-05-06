#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>


if __name__=="__main__":
    import scapy
    from scapy.all import *
    import socket
    #<----- for local testing only
    sys.path.append("../scapy/layers")
    from ssl_tls import *
    #------>
    
    
    target = ('www.remote.host',443)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord()/ \
        TLSHandshake()/ \
        TLSClientHello(compression_methods=range(0xff), 
                       cipher_suites=range(0xff), 
                       extensions=[
                                   TLSExtension()/ \
                                  TLSALPN(protocol_name_list= \
                                                    [TLSALPNProtocol(data="http/1.0"),
            
                                                     ])
                                   ],)
                
    p.show()

    
    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(1024)
    print "received, %s"%repr(resp)
    resp = SSL(resp)
    resp.show()
    s.close()


    # experimental server code
    '''
    target = ('192.168.220.1',4433)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(target)
    s.listen(1)
    conn, addr = s.accept()
    print 'Connected by', addr
    while 1:
        data = conn.recv(1024)
        print "lol"
        del (resp[TLSRecord].length)
        del (resp[TLSHandshake].length)
        del (resp[TLSServerHello].extensions_length)
        resp[TLSServerHello].cipher_suite=0x04
        resp[TLSServerHello].extensions.append(
                                       TLSExtension()/ \
                                       TLSALPN(protocol_name_list= \
                                                        [TLSALPNProtocol(data="h"*250),
                                                         ])
                                       )
        resp[TLSRecord].show()
        conn.sendall(str(resp[TLSRecord]))
    conn.close()
    print "bound"
    #s.connect(target)
    
    resp = s.recv(1024)
    print "received, %s"%repr(resp)
    SSL(resp).show()
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord()/ \
        TLSHandshake()/ \
        TLSServerHello(compression_method=0x00, 
                       cipher_suite=0x00, 
                       extensions=[
                                   TLSExtension()/ \
                                  TLSALPN(protocol_name_list= \
                                                    [TLSALPNProtocol(data="http/1.0"),
                                                     ])
                                   ],)
                
    p.show()

    
    print "sending TLS payload"
    s.sendall(str(p))

    
    
    s.close()
    '''
    
    
    