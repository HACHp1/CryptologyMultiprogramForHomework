from CryptologyMultiprogram import DES
from CryptologyMultiprogram import RSA
from CryptologyMultiprogram import sha1

s='4e6574776f726b205365637572697479'

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

#明文
message = 'Network Security'
#DES密钥
DESkey = 'WilliamS'




#生成接收方各密钥并临时存储
RSA.genKeys()
metaReceive=RSA.meta

#生成发送方各密钥并临时存储
RSA.genKeys()
metaSend=RSA.meta


#加密传输DES密钥

RSA.meta=metaReceive

deskeyencrypted=hex(RSA.bin_pow(str2int(DESkey),RSA.meta['e'],RSA.meta['n']))

deskeydecrypted=RSA.bin_pow(int(deskeyencrypted[2::],16),RSA.meta['d'],RSA.meta['n'])

deskeydecryptedstr=int2str(deskeydecrypted)

# print('DESkey  '+deskeydecryptedstr)



#DES加密
cypherdes = DES.DES_encrypt(message, DESkey)

#SHA1信息摘要
digest=sha1.sha1(message).hexdigest()


#RSA私钥身份鉴别（使用加密方私钥
RSA.meta=metaSend
authen=RSA.bin_pow(str2int(digest),RSA.meta['d'],RSA.meta['n'])


#拼接完整密文信息
cypher=hex(cypherdes)+'|'+hex(authen)


#接收方

#拆解密文

outputC=cypher.split('|')

# print(outputC)
# print(outputC[0][2::])

# print(ord(deskeydecryptedstr[8]))
# print('len '+str(len(deskeydecryptedstr)))
#由于某一步（似乎是DES加密）使字符串后多了00，这里需要截取

messageR=DES.DES_decrypt(int(outputC[0][2::],16),deskeydecryptedstr[:8:])
print(messageR)

digestR=sha1.sha1(messageR).hexdigest()

RSA.meta=metaSend
digestR2=RSA.bin_pow(int(outputC[1][2::],16),RSA.meta['e'],RSA.meta['n'])

print(digestR)
print(int2str(digestR2))
digestR2=int2str(digestR2)

print(len(digestR))
print(len(digestR2))
if(digestR==digestR2[:-1:]):
    print('OK')



