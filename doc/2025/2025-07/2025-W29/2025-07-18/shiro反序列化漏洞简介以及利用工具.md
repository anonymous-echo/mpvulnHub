> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MzkwNDU1Mw==&mid=2247485836&idx=1&sn=4b0f85e591199fb6b48f4f133b53af19

#  shiro反序列化漏洞简介以及利用工具  
原创 信安路漫漫  信安路漫漫   2025-07-17 23:00  
  
# shiro简介  
  
Apache Shiro是一个强大且易用的  
Java安全框架  
,执行身份验证、授权、密码和会话管理。使用Shiro的易于理解的API,可以快速、轻松地获得任何应用程序,从最小的移动应用程序到最大的网络和企业应用程序。内置了可以连接大量安全数据源（又名目录）的Realm，如LDAP、关系数据库（JDBC）、类似INI的文本配置资源以及属性文件等。  
# 指纹识别  
  
判断是否使用了shiro，一般在响应包里面存在rememberme=deleteMe  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nByKMnXGvL0cDS2VvvPoTsv1PwZzVV9fc5ictXaunzSHFOqdPs4UZjWjtwibzuqZ1fyqdmUYjezIcvqA/640?wx_fmt=png&from=appmsg "")  
# 资产收集：  
  
Fofa语法 ：  
  
"shiro" &&"管理系统"  
  
header="rememberme=deleteMe"、header="shiroCookie"  
# shiro反序列化漏洞  
  
漏洞的利用点是在cookie里的rememberMe参数，这个参数的值是AES加密再base64之后设置在cookie中的。在服务端对rememberMe的cookie值的操作应该是先base64解码然后AES解密再反序列化，就导致了反序列化RCE漏洞。  
  
服务端接收rememberMe的cookie值：  
  
rememberMe的cookie值=>base64解码=>AES解密=>反序列化  
  
我们要利用那么POC就需要先反序列化然后再AES加密最后base64编码  
  
Payload产生的过程：  
  
命令=>序列化=>AES加密=>base64编码=>payloadfunction(){    
  
在shrio中AES加密有一个iv向量但是没有用到所以随机生成一个就可以了，重要的是密钥密钥，如果没有修改默认的密钥那么就很容易就知道密钥了，之后就是编写POC了。  
  
  
利用该漏洞需要找到一个利用链，以及密钥  
  
# shiro反序列化漏洞工具  
## burp插件检测  
  
可以检测项目是否使用了shiro以及检测密钥  
  
https://github.com/pmiaowu/BurpShiroPassiveScan  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nByKMnXGvL0cDS2VvvPoTsv1oEvwU2h2hVZksjxZna0X9XicLcYMhcCr0pRogzDbmicUFfgrIDGnCEibw/640?wx_fmt=png&from=appmsg "")  
## 漏洞利用工具  
  
https://github.com/pmiaowu/BurpShiroPassiveScan  
  
使用的过程中可以先爆破密钥，然后在爆破利用链，接下来就可以进行利用了  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nByKMnXGvL0cDS2VvvPoTsv1GSetqfYibGhhbqEOricJAy8zU4ERkplkKhOzJb9zSSR868dibHKITgn7g/640?wx_fmt=png&from=appmsg "")  
  
  
  
