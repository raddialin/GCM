from Crypto.Cipher import AES
import base64
import binascii
import math
import conversions
def galois2(bin_x, bin_y):
    if(len(bin_x)!=128):
        pad=128-len(bin_x)
        bin_x='0'*pad+bin_x
    if(len(bin_y)!=128):
        pad=128-len(bin_y)
        bin_y='0'*pad+bin_y
    z='0'*128
    i=0
    v=bin_y
    r='11100001'+'0'*120
    while(i<127): #changed 128 to 127
        #print str(i)+': '+z
        if(v[127]==0):
            new_v=shift(v)
        else:
            new_v=xor(shift(v),r)
        if(bin_x[i]==0):
            new_z=z
        else:
            new_z=xor(z,v)
        v=new_v
        z=new_z
        #print str(i)+': '+z
        i=i+1
    return z
def galois(x, y):
    z = ''
    for i in range(128):
        z += str('0')
    v = x
    r = "11100001"
    for i in range(120):
        r += str('0')
    for j in range(127):
        if (y[j] == "1"):
            z = ''.join(map(str, conversions.as_to_lis(conversions.xor(z, v))))
        if (v[127] == "0"):
            v = rightshift(v)
        else:
            v = ''.join(map(str, conversions.as_to_lis(conversions.xor(rightshift(v), r))))
    return z
def ghash(h,x):
    m=len(x)/128
    y='0'*128
    for i in range(0,m):
        sub_x=x[128*i:128*i+128]
        print bin_to_hex(xor(y,sub_x))
        new_y=galois(xor(y,sub_x),h)
        #print bin_to_hex(new_y)
        y=new_y
    return y
def gctr(key, icb, x): #cb needs to be size 16
    n=int(math.ceil(len(x)/128.))
    cb=icb
    print (icb)
    i=1
    j=2
    y=''
    while (i<n-1):
        y=y+xor(x[128*i:128*i+128],ECB_encrypt(key,cb))
        cb=increment(32,cb)
        i=i+1
    remainder=x[128*(n-2):]
    y=y+xor(remainder,ECB_encrypt(key,cb)[0:len(remainder)])
    return y
def gcm(key, iv, p, a, tag_length): #pad to 128 bits
    p=str_to_bin(p)
    a=str_to_bin(a)
    h=ECB_encrypt(key,'0'*16) #128 bit 0 in bytes
    #print h
    length=bin(len(iv))[2:]
    if(len(length)!=64):
        pad=128-len(length)
        length='0'*pad+length
    length_a=bin(len(a))[2:]
    if(len(length_a)!=64):
        pad=128-len(length_a)
        length_a='0'*pad+length_a
    if(len(iv)==96):
        j=iv+'0'*31+'1'
    else:
        s=int(128*math.ceil(len(iv)/128.))-len(iv)
        j=ghash(h, iv+'0'*(s+64)+length)
    c=gctr(key, increment(32,j),p)
    length_c=bin(len(c))[2:]
    if(len(length_c)!=64):
        pad=128-len(length_c)
        length_c='0'*pad+length_c
    u=int(128*math.ceil(len(c)/128.)-len(c))
    v=int(128*math.ceil(len(a)/128.)-len(a))
    s=ghash(h,a+('0'*v)+c+('0'*u)+length_a+length_c)
    t=gctr(key,j,s)[0:tag_length]
    return (c,t)
    
    
def shift(s):
    out='0'+s
    return out[0:len(out)-1]
def xor(s1,s2):
    #print 's1'+s1
    #print 's2'+s2
    out=''
    for i in range(0,len(s1)):
        if (s1[i]==s2[i]):
            out=out+'0'
        else:
            out=out+'1'
    return out
def increment(s,x):
    msb=x[0:len(x)-s]
    lsb=pow(int(x[-s:],2)+1,1,pow(2,s))
    lsb=bin(lsb)[2:]
    if (len(lsb)!=s):
        pad=s-len(lsb)
        lsb='0'*pad+lsb
    return msb+lsb
def ECB_encrypt(key, data): #needs input data of size 16
    #print 'data: '+data
    cipher=AES.new(key, AES.MODE_ECB)
    #print cipher.encrypt(data)
    return ascii_to_bin(base64.b64decode(base64.b64encode(cipher.encrypt(data))))
def ascii_to_bin(inp):
    #print len(inp)
    x=[ord(c) for c in inp]
    out=''
    for i in x:
        o=bin(i)[2:]
        if(len(o)!=8):
            pad=8-len(o)
            o='0'*pad+o
        out=out+o
    return out
def str_to_bin(s):
    out=''
    for i in s:
        out=out+bin(ord(i))[2:]
    return out
def hex_to_bin(s):
    out=''
    for i in s:
        if (i=='0'):
            out=out+'0000'
        if (i=='1'):
            out=out+'0001'
        if (i=='2'):
            out=out+'0010'
        if (i=='3'):
            out=out+'0011'
        if (i=='4'):
            out=out+'0100'
        if (i=='5'):
            out=out+'0101'
        if (i=='6'):
            out=out+'0110'
        if (i=='7'):
            out=out+'0111'
        if (i=='8'):
            out=out+'1000'
        if (i=='9'):
            out=out+'1001'
        if (i=='a'):
            out=out+'1010'
        if (i=='b'):
            out=out+'1011'
        if (i=='c'):
            out=out+'1100'
        if (i=='d'):
            out=out+'1101'
        if (i=='e'):
            out=out+'1110'
        if (i=='f'):
            out=out+'1111'
    return out
def format_key(key):
    return hex_to_bin(binascii.hexlify(key))
def bin_to_hex(s):
    out=''
    num=(len(s)/4)
    x=0
    while(x<num):
        i=s[4*x:4*x+4]
        if (i=='0000'):
            out=out+'0'
        if (i=='0001'):
            out=out+'1'
        if (i=='0010'):
            out=out+'2'
        if (i=='0011'):
            out=out+'3'
        if (i=='0100'):
            out=out+'4'
        if (i=='0101'):
            out=out+'5'
        if (i=='0110'):
            out=out+'6'
        if (i=='0111'):
            out=out+'7'
        if (i=='1000'):
            out=out+'8'
        if (i=='1001'):
            out=out+'9'
        if (i=='1010'):
            out=out+'a'
        if (i=='1011'):
            out=out+'b'
        if (i=='1100'):
            out=out+'c'
        if (i=='1101'):
            out=out+'d'
        if (i=='1110'):
            out=out+'e'
        if (i=='1111'):
            out=out+'f'
        x=x+1
    return out
def rightshift(v):
    n = "0"
    n += str(v[:len(v)-1])
    return n

