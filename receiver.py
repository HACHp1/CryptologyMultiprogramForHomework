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


port = 8082
s1 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
#从给定的端口，从任何发送者，接收UDP数据报
s1.bind(("",port))
print ('waiting on port:',port)


def receiv():
    datad=b''
    while(1):
        data,addr = s1.recvfrom(1024)
        datad+=data
        if(len(data)<1024):
            break
    return datad

def send(mystr):
    port=8081
    host='127.0.0.1'
    s2=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s2.sendto(mystr,(host,port))


if __name__=='__main__':
    # 生成接收方各密钥并临时存储
    RSA.genKeys()
    metaReceive = RSA.meta
    send(str(metaReceive['e']).encode('utf-8'))
    send(str(metaReceive['n']).encode('utf-8'))
    # print(str(metaReceive['e']))

    deskeyencrypted=receiv().decode('utf-8')

    deskeydecrypted = RSA.bin_pow(int(deskeyencrypted[2::], 16), RSA.meta['d'], RSA.meta['n'])

    deskeydecryptedstr = int2str(deskeydecrypted)

    # print('key+'+deskeydecryptedstr)

    cypher=receiv().decode('utf-8')

    # 接收方

    # 拆解密文

    outputC = cypher.split('|')

    # print(outputC)
    # print(outputC[0][2::])

    # print(ord(deskeydecryptedstr[8]))
    # print('len '+str(len(deskeydecryptedstr)))
    # 由于某一步（似乎是DES加密）使字符串后多了00，这里需要截取

    messageR = DES.DES_decrypt(int(outputC[0][2::], 16), deskeydecryptedstr[:8:])
    print('message received is:'+messageR)

    digestR = sha1.sha1(messageR).hexdigest()

    e=receiv().decode('utf-8')
    n=receiv().decode('utf-8')

    digestR2 = RSA.bin_pow(int(outputC[1][2::], 16),int(e) , int(n))

    # print(digestR)
    # print(int2str(digestR2))
    digestR2 = int2str(digestR2)

    # print(len(digestR))
    # print(len(digestR2))
    if (digestR == digestR2[:-1:]):
        print('Athentication passed!')
