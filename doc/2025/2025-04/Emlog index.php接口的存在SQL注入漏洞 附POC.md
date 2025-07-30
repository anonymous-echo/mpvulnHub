#  Emlog index.php接口的存在SQL注入漏洞 附POC   
2025-4-7更新  南风漏洞复现文库   2025-04-07 23:44  
  
   
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. Emlog 简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
Emlog  
## 2.漏洞描述  
  
EMLOG 是一款轻量级开源博客和CMS建站系统，速度快、省资源、易上手，适合各种规模的站点搭建。Emlog index.php接口的存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
Emlog  
![Emlog index.php接口的存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5p1eoUqp6rVfic7XBpb4x0ReQLaGOStG0wTibecwbCZwLoYKpS8I6ehULQ/640?wx_fmt=png&from=appmsg "null")  
  
Emlog index.php接口的存在SQL注入漏洞  
## 4.fofa查询语句  
  
app="EMLOG"  
## 5.漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5p0rRP1tJXiaqdiblx0JHymJJLqlPJMJHOibiaDQfcwia4dNQvSuJVOEO56oA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
可以跑sqlmap  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5pibBfdwII24pO2s2icNbicNPu538CwPQh7L4z0mVPfVlyqib7r0MxcEzjQQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5p0dmxRUnMDQZoJTpP7l4LMEvOD1iavQ63ibuEqMUibwAFySQRDNnDlPl5g/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5pcMnCgJj38S2MYE3e6YmSdptRwb32Z2812SAws0FndogxRJThlNal2A/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5pSNxfrNybuSRoAM7yx5jNqyjqp7zicBHXljew7YiazSjPxUvRz8qxNiaaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5pjGczYvPnLIYrljCZdeGAzibyZUWQnZjkxgt8o3blSndLRY5fUEjEhiag/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a8n4O8CcemPYgGUx8fsR5piaRDFSzD55uoBJnkgY0XrgIUGiblQ6q55dlIFlwY1qFbyk84SDlJQKuQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
