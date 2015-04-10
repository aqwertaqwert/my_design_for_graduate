#coding:utf-8
#python 检测文件MD5值
#python version 2.6

import hashlib
import os

#简单的测试一个字符串的MD5值
src = 'teststring'
print (hashlib.md5(src).hexdigest().upper())
#hexdigest() 为十六进制值，digest()为二进制值

#使用update
m0=hashlib.md5()
m0.update(src)
print m0.hexdigest().upper()

#一个小文件的MD5值
filename = 'c:\\boot.ini'
f = file(filename,'rb')
m1 = hashlib.md5()
m1.update(f.read(8096))
print m1.hexdigest().upper()
f.close()

#大文件的MD5值
def GetFileMd5(filename):
    if not os.path.isfile(filename):
        return
    myhash = hashlib.md5()
    f = file(filename,'rb')
    while True:
        b = f.read(8096)
        if not b :
            break
        myhash.update(b)
    f.close()
    return myhash.hexdigest().upper()

print GetFileMd5("c:\\a.rar")

