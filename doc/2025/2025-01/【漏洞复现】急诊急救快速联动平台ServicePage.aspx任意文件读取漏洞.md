#  【漏洞复现】急诊急救快速联动平台ServicePage.aspx任意文件读取漏洞   
原创 清风  白帽攻防   2025-01-07 01:05  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
互慧急诊急救快速联动平台是一个专门用于管理门诊急诊病人的系统，分为两大主要功能模块：门诊急诊业务和急诊物资管理。门诊急诊业务包括院前急救、院内抢救、留观监护、绿色通道、预检分诊等方面；急诊物资管理则涵盖了急诊药品、设备、抢救车、急救箱等相关物资的管理和使用。该平台旨在通过优化急诊流程、规范抢救操作、确保急诊物资的合理使用，最终提高抢救成功率，确保患者的生命安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0f5eicbRy4HT576ETApbtSibFbxbiaKhMzErapqfzNYDIhzSbeqrDsIExFl1iaHT7tiaFymLW3OGG133ZA/640?wx_fmt=png&from=appmsg "")  
漏洞描述  
  
急诊综合管理平台的 ServicePage.aspx 接口存在任意文件读取漏洞。攻击者无需进行身份验证即可利用该漏洞读取系统中的重要文件，例如数据库配置文件、系统配置文件等。  
fofa语法```
body="/emis_lib/js/ThreeExtras.js"
```  
#### 漏洞复现  
```
具体poc详情请在公众号知识星球获取
XXX HTTP/1.1
Host: IP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Connection: close
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0f5eicbRy4HT576ETApbtSibFg9RmhTSr5ONqpB23QaqhWOYZuibXnuakObRlNDO4RbibTlZsuHaSlTEg/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0f5eicbRy4HT576ETApbtSibFctmD69Sj5CYzJvJjyDYD0zQafndD8kq4Kricp4EOMDFmtLSOmXGibthw/640?wx_fmt=png&from=appmsg "")  
修复建议  
1、限制互联网暴露面或接口访问权限  
  
2、升级到安全版本  
  
