#  灵当CRM Ambassador接口处存在SQL注入漏洞 漏洞预警   
2025-2-26更新  南风漏洞复现文库   2025-02-26 15:19  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 灵当CRM 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
灵当CRM致力于为企业提供客户管理数字化、销售管理自动化、服务管理智能化、项目管理一体化的个性化CRM行业解决方案。  
## 2.漏洞描述  
  
灵当CRM致力于为企业提供客户管理数字化、销售管理自动化、服务管理智能化、项目管理一体化的个性化CRM行业解决方案,构建全生命周期的数字化管理体系,实现可持续的业绩增长!。灵当CRM Ambassador接口处存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
灵当CRM  
  
![灵当CRM Ambassador接口处存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Ysql2qpa7cua3vvePHtKhLZJ2uqMicI5sQ7icJ3sTGOgSia8knfENY7DyXxBOAKPpJIU4ktEUPibab7Q/640?wx_fmt=png&from=appmsg "null")  
  
灵当CRM Ambassador接口处存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="crmcommon/js/jquery/jquery-1.10.1.min.js" || (body="http://localhost:8088/crm/index.php" && body="ldcrm.base.js")  
## 5.漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Ysql2qpa7cua3vvePHtKhLd1yrFUKBvUj1rVRsl0DhEK5OycsODlT16LgwS0sTLxIoyYvQFvRFTA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Ysql2qpa7cua3vvePHtKhLhqniaSl6AuZcSgoLmveDUKhia5WxQa6D6iacibFibDHHzLq7DZWnTlyBKmQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Ysql2qpa7cua3vvePHtKhLjR9unniaNOyeeTrCd0hTtc3SnFJp12ic9ic61fCummgICHSP1jScVrlbg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Ysql2qpa7cua3vvePHtKhLiaUbgajwwdkcx2Bj8O8jwPHWYahEOt7qUHrCaI4k5TX6MxBUoYM4pGQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Ysql2qpa7cua3vvePHtKhLVz6Al282G3ibCTdVr2amUibyONyNkuXFj9Lhss4kHqupiam03jnia0Uo5A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Ysql2qpa7cua3vvePHtKhLVT77Lncyw49BFElfIyuUAG6nXT6YicJBbX9sicIXKRDvNpNXdLIO61FQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
  
