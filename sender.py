import socket
from CryptologyMultiprogram import DES
from CryptologyMultiprogram import RSA
from CryptologyMultiprogram import sha1



#将hex字符串转化为字符串
def hex2str(s):
    i=0
    mystr=''
    while(i<len(s)):
        mystr+=chr(16*int(s[i],16)+int(s[i+1],16))
        i+=2
    return mystr

#将int转化为字符串（乱码）
def int2str(encrypted_result):
    return hex2str(hex(encrypted_result)[2::])

# 将短字符串转为int
def str2int(mystr):
    i=0
    myint=0
    while(i<len(mystr)):
        myint+=ord(mystr[i])*pow(pow(2,8),len(mystr)-i)
        i+=1
    return  myint

port = 8081
s1 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
#从给定的端口，从任何发送者，接收UDP数据报
s1.bind(("",port))


port=8082
host='127.0.0.1'
s2=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)



def receiv():
    datad=b''
    while(1):
        data,addr = s1.recvfrom(1024)
        datad+=data
        if(len(data)<1024):
            break
    return datad

def send(mystr):
    s2.sendto(mystr,(host,port))


if __name__=='__main__':
    #明文
    message = 'Network Security'
    #DES密钥
    DESkey = 'WilliamS'

    # 生成发送方各密钥并临时存储
    RSA.genKeys()
    metaSend = RSA.meta
    #加密传输DES密钥

    e=receiv().decode('utf-8')
    n=receiv().decode('utf-8')
    # print('e:'+e)
    deskeyencrypted=hex(RSA.bin_pow(str2int(DESkey),int(e),int(n)))

    send(deskeyencrypted.encode('utf-8'))



    #DES加密
    cypherdes = DES.DES_encrypt(message, DESkey)

    #SHA1信息摘要
    digest=sha1.sha1(message).hexdigest()


    #RSA私钥身份鉴别（使用加密方私钥
    RSA.meta=metaSend
    authen=RSA.bin_pow(str2int(digest),RSA.meta['d'],RSA.meta['n'])


    #拼接完整密文信息
    cypher=hex(cypherdes)+'|'+hex(authen)

    send(cypher.encode('utf-8'))

    send(str(metaSend['e']).encode('utf-8'))
    send(str(metaSend['n']).encode('utf-8'))