from Crypto.Cipher import AES
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
            z = ''.join(map(str, as_to_lis(xor2(z, v))))
        if (v[127] == "0"):
            v = rightshift(v)
        else:
            v = ''.join(map(str, as_to_lis(xor2(rightshift(v), r))))
    return z
# the input for k, iv, p, a are in hexadecimal, and t is the number of hex characters for the tag
def encryption(k, iv, p, a, t):
    h=ECB_encrypt(k,'0'*32)
    h=hex_to_bin(h)
    iv=hex_to_bin(iv)
    if (len(iv)==96):
        y=[iv+'0'*31+'1']
    else:
        y=[ghash(h,'',iv)]
    p=hex_to_bin(p)
    a=hex_to_bin(a)
    if(len(p)%128==0):
        n=len(p)/128
    else:
        n=(len(p)/128)+1
    for i in range(1,n+1):
        y+=[increment(32,y[i-1])] 
    new_y=[]
    for i in y:
        new_y+=[bin_to_hex(i)]
    length_p=len(p)%128
    if(length_p==0):
        length_p=128
    i=1
    c_list=[]
    while(i<n):
        s=p[128*(i-1):128*(i-1)+128]
        c_list+= [xor(s,hex_to_bin(ECB_encrypt(k,new_y[i])))]
        i=i+1
    if(c_list==[]):
        c_list+=[xor(p,hex_to_bin(ECB_encrypt(k,new_y[n]))[0:length_p])]
    else:
        c_list+=[xor(p[128*(n-1):],hex_to_bin(ECB_encrypt(k,new_y[n]))[0:length_p])]
    c=''
    for i in c_list:
        c+=i
    tag=xor(ghash(h,a,c),hex_to_bin(ECB_encrypt(k,new_y[0])))[0:t*4]
    return (bin_to_hex(c),bin_to_hex(tag))
#the input for k, iv, c, a, tag are in hexadecimal
def decryption(k, iv, c, a ,tag):
    h=ECB_encrypt(k,'0'*32)
    h=hex_to_bin(h)
    iv=hex_to_bin(iv)
    if (len(iv)==96):
        y=[iv+'0'*31+'1']
    else:
        y=[ghash(h,'',iv)]
    c=hex_to_bin(c)
    a=hex_to_bin(a)
    new_tag=bin_to_hex(xor(ghash(h,a,c),hex_to_bin(ECB_encrypt(k,bin_to_hex(y[0]))))[0:len(tag)*4])
    if (new_tag!=tag):
        return 'FAIL'
    else:
        if(len(c)%128==0):
            n=len(c)/128
        else:
            n=(len(c)/128)+1
        for i in range(1,n+1):
            y+=[increment(32,y[i-1])] 
        new_y=[]
        for i in y:
            new_y+=[bin_to_hex(i)]
        length_c=len(c)%128
        if(length_c==0):
            length_c=128
        i=1
        p_list=[]
        while(i<n):
            s=c[128*(i-1):128*(i-1)+128]
            p_list+= [xor(s,hex_to_bin(ECB_encrypt(k,new_y[i])))]
            i=i+1
        if(p_list==[]):
            p_list+=[xor(c,hex_to_bin(ECB_encrypt(k,new_y[n]))[0:length_c])]
        else:
            p_list+=[xor(c[128*(n-1):],hex_to_bin(ECB_encrypt(k,new_y[n]))[0:length_c])]
        p=''
        for i in p_list:
            p+=i
        return bin_to_hex(p)
def ghash(h,a,c):
    if(len(a)%128==0):
        m=len(a)/128
    else:
        m=(len(a)/128)+1
    if(len(c)%128==0):
        n=len(c)/128
    else:
        n=(len(c)/128)+1
    if(a==''):
        m=0
    x=['0'*128]
    for i in range(1,m):
        s=a[128*(i-1):128*(i-1)+128]
        x+=[galois(xor(x[i-1],s),h)]
    if(a!=''):
        last_a=a[128*(m-1):]
        if(len(a)%128!=0):
            last_a=last_a+'0'*(128-(len(a)%128))
        x+=[galois(xor(x[-1],last_a),h)]
    for i in range(1,n):
        s=c[128*(i-1):128*(i-1)+128]
        x+=[galois(xor(x[-1],s),h)]
    last_c=c[128*(n-1):]
    if(len(c)%128!=0):
        last_c=last_c+'0'*(128-(len(c)%128))
    x+=[galois(xor(x[-1],last_c),h)]
    length_a=bin(len(a))[2:]
    length_c=bin(len(c))[2:]
    if(length_a!=64):
        length_a='0'*(64-len(length_a))+length_a
    if(length_c!=64):
        length_c='0'*(64-len(length_c))+length_c
    if(a==''):
        length_a='0'*64
    length=length_a+length_c
    x+=[galois(xor(x[-1],length),h)]
    return x[-1]
def xor(s1,s2):
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
def ECB_encrypt(key, data):
    key=hex_to_as(key)
    data=hex_to_as(data)
    cipher=AES.new(key, AES.MODE_ECB)
    return as_to_hex(cipher.encrypt(data))
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
def as_to_lis(asrep):
    return [ord(c) for c in asrep]
def xor2(s1,s2):
    le=min(len(s1),len(s2))
    s=''
    for j in range(le):
        s+=chr(ord(s1[j])^ord(s2[j]))
    return s
def as_to_hex(asrep):
    return lis_to_hex(as_to_lis(asrep))
def lis_to_hex(lisrep):
    hexrep=''
    for x in lisrep:
        if x>=16:
            hexrep+=(hex(x)[2:])
        else:
            hexrep+=('0'+hex(x)[2:])
    return hexrep
def hex_to_as(hexrep):
    return lis_to_as(hex_to_lis(hexrep))
def lis_to_as(lisrep):
    s=''
    for x in lisrep:
        s+=chr(x)
    return s
def hex_to_lis(hexrep):
    return([int(hexrep[2*i:2*i+2],16) for i in range(len(hexrep)/2)])
    return hexrep
