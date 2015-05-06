#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : janglin <http://japrogbits.blogspot.co.at>
# http://japrogbits.blogspot.co.at/2011/02/using-encrypted-data-between-python-and.html
import binascii
import StringIO
class PKCS7Encoder(object):
     '''
     RFC 2315: PKCS#7 page 21
     Some content-encryption algorithms assume the
     input length is a multiple of k octets, where k > 1, and
     let the application define a method for handling inputs
     whose lengths are not a multiple of k octets. For such
     algorithms, the method shall be to pad the input at the
     trailing end with k - (l mod k) octets all having value k -
     (l mod k), where l is the length of the input. In other
     words, the input is padded at the trailing end with one of
     the following strings:
 
              01 -- if l mod k = k-1
             02 02 -- if l mod k = k-2
                         .
                         .
                         .
           k k ... k k -- if l mod k = 0
 
     The padding can be removed unambiguously since all input is
     padded and no padding string is a suffix of another. This
     padding method is well-defined if and only if k < 256;
     methods for larger k are an open issue for further study.
     '''
     def __init__(self, k=16):
         self.k = k

     ## @param text The padded text for which the padding is to be removed.
     # @exception ValueError Raised when the input padding is missing or corrupt.
     def decode(self, text):
         '''
         Remove the PKCS#7 padding from a text string
         '''
         nl = len(text)
         val = int(binascii.hexlify(text[-1]), 16)
         if val > self.k:
             raise ValueError('Input is not padded or padding is corrupt')
 
         l = nl - val
         return text[:l]
 
     ## @param text The text to encode.
     def encode(self, text):
         '''
         Pad an input string according to PKCS#7
         '''
         l = len(text)
         output = StringIO.StringIO()
         val = self.k - (l % self.k)
         for _ in xrange(val):
             output.write('%02x' % val)
         return text + binascii.unhexlify(output.getvalue())
    
    ## @param text The text to encode.
     def encode_tls10(self, text):
         '''
         Pad an input string according to PKCS#7
         '''
         k = self.k -1          # mod k-1 due to padlen byte
         l = len(text)
         output = StringIO.StringIO()
         val = k - (l % self.k) 
         for _ in xrange(val+1):
             output.write('%02x' % val)
         return text + binascii.unhexlify(output.getvalue())
     
     
if __name__=="__main__":
    p=PKCS7Encoder()
    print '4444440a9f51e3f0a916224bf220379fc032f373a0abec7f0707070707070707'==p.encode_tls10("44 44 44 0a 9f 51 e3 f0 a9 16 22 4b f2 20 37 9f c0 32 f3 73 a0 ab ec 7f".replace(" ","").decode("hex")).encode("hex")