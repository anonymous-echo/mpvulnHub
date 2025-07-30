#  某一次PDF-XSS漏洞挖掘(安服系列)   
原创 漏洞谷  漏洞谷   2024-05-18 11:35  
  
```
免责声明：
1.禁止未授权的渗透测试
2.该文章仅供学习参考，切勿拿去尝试
3.此文所提供的信息而造成的任何后果及损失，均由使用者本人负责
4.一切后果与文章作者无关
5.文章所涉及的全部漏洞，均是被修复完漏洞后才公开
```  
  
一.漏洞名称  
```
PDF-XSS
```  
  
二.风险级别  
```
自评：中危
```  
  
三.漏洞描述  
```
PDF-XSS（Portable Document Format Cross-Site Scripting）是一种利用PDF文件中的漏洞实现的跨站点脚本攻击。
PDF文件是一种常见的电子文档格式，其中包含了丰富的内容，包括图像、文本、链接等等。攻击者可以通过在PDF文件中插入恶意代码，例如JavaScript脚本，来实现PDF-XSS攻击。
PDF-XSS攻击可以在用户打开PDF文件时触发，当用户点击恶意链接或执行特定操作时，恶意代码就会被执行。攻击者可以利用PDF XSS攻击来窃取用户敏感信息、篡改网站内容、实施网络钓鱼等行为。
```  
  
四.漏洞证明  
  
4.1漏洞位置  
```
注册-->登录--->个人中心-->开发者--->个人开发者-->资料上传，上传pdf文件
```  
  
4.2先注册  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTmCibA9Lc3cCTCsOammGjAl4HonE4icDOe2WOGd2IYPbZcOf0TnQLkByw/640?wx_fmt=png&from=appmsg "")  
  
4.3 注册成功后。进行登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTuqsYa3p31iblcwDFrib8xiazsIFZUFS43zZTkhhC0PN0ehlhLL5gfnuIQ/640?wx_fmt=png&from=appmsg "")  
  
4.4进入个人中心  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTicNslyQ4gmJ3l95RKSTHPHr7FMBtjjU2l59r8MAKqVxMjm1wIs1uTIw/640?wx_fmt=png&from=appmsg "")  
  
4.5选择进入个人开发者中心后，有一个上传文件的功能，  
上传  
pdf文即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTQftzahW0BeMbToUHNFaMuGjwic80y5B3luRybt91WVMicRhiclxUKOVqg/640?wx_fmt=png&from=appmsg "")  
  
4.6上传pdf文件过后，会生成一个加密后的文件编码  
```
11********************3f
```  
  
但是这个有一个小小的问题？  
  
你上传的pdf文件，他这个网站不能在线预览pdf文件(或者是他没有预览文件的功能)，他只能下载后自己在本地才可以打开文件，那么这样还算漏洞吗？？？  
  
这样肯定不能算吧  
  
所以说，要怎么才能通过在线预览pdf文件，从而来触发漏洞的产生呢？  
  
所以这个时候，我一般会多看看去寻找一些其他的功能点，看能不能通过其他的功能点来结合刚刚上传的文件来触发。另外一个就是通过js文件寻找一些可以利用的接口，来进行尝试。  
  
我这里是使用最傻逼的方式，下面直接说我是怎么搞的吧  
  
网址中这里有一个在线下载的功能，我通过在线下载的功能点进行抓包，观察后发现，下载的功能点后面拼接着  
加密后的文件编码所以我这里就通过  
遍历  
接收  
传参值的参数  
```
下载功能的接收传参值：contractDownLoad
http://127.0.0.1/**/**/**/**/**/contractDownLoad?fileId=11***************3f
```  
  
通过遍历获得的预览参数值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTV8p4H9sw2MO7etmbV0cajYv1b9VS40hUrjL2fzichZFSp6wtvnEfgzw/640?wx_fmt=png&from=appmsg "")  
```
预览功能的接收传参值：html
http://127.0.0.1/**/**/**/**/**/html?fileId=11***************3f
```  
  
最后拼接参数然后访问链接，来触发漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTVwVTaay0fhiaLwP27Tib5QjLn2kkZWLLg2dB9IQh07UuBvRgJpw6CkRA/640?wx_fmt=png&from=appmsg "")  
  
五.整改方案  
```
1.过滤输入内容：开发人员应该对用户上传的PDF文件进行过滤，确保其中不包含恶意脚本等内容。
2.禁用脚本：PDF文件中的JavaScript脚本是攻击者利用PDF XSS漏洞的主要手段之一，因此，禁用PDF文件中的JavaScript脚本可以有效地防止PDF XSS攻击。可以通过使用PDF阅读器的安全设置来禁用脚本。
3.更新软件：PDF阅读器的安全漏洞可能会导致PDF XSS攻击，因此，使用最新版本的PDF阅读器可以有效地减少PDF XSS漏洞的风险。
4.使用第三方插件解析pdf，不用chrome自带的pdf解析。
5.不允许用户直接打开pdf文件，而是必须下载到本地后才能打开pdf文件。
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTjl6gspHiaDj4G8vYoH7FhWnTpFS8wkibEpdPunicrr4w3tElVkf8JjPKw/640?wx_fmt=gif&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_gif/PnNLap9B4bUy1GqUu441GfibpCdb9r1jTjl6gspHiaDj4G8vYoH7FhWnTpFS8wkibEpdPunicrr4w3tElVkf8JjPKw/640?wx_fmt=gif&from=appmsg "")  
  
