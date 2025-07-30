#  用友crm客户关系管理ajax/getufvouchdata.php接口存在SQL注入漏洞 漏洞预警   
2025-3-19更新  南风漏洞复现文库   2025-03-19 23:15  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友crm客户关系管理简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友U8客户关系管理全面解决方案是基于中国企业最佳营销管理实践，更符合中国企业营销管理特点，客户关系管理的整合营销平台。产品融合数年来积累的知识、方法和经验，目标是帮助企业有效获取商机、提升营销能力。  
## 2.漏洞描述  
  
用友U8客户关系管理全面解决方案是基于中国企业最佳营销管理实践，更符合中国企业营销管理特点，客户关系管理的整合营销平台。用友crm客户关系管理ajax/getufvouchdata.php接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友U8 CRM  
  
![用友crm客户关系管理ajax/getufvouchdata.php接口存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpdGWVx9fkDHasibNpfriaibY8ibL3JNcNEafzacQjhGRF31Q1CnJ9ic8vaEeA/640?wx_fmt=png&from=appmsg "null")  
  
用友crm客户关系管理ajax/getufvouchdata.php接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
title="用友U8CRM"  
## 5.漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpdYtFYJibfCeu1yf9YUQjZSeO7uNYXSzgklRLBwtr44PlYKRsmD6uUq7w/640?wx_fmt=jpeg&from=appmsg "null")  
  
可以跑sqlmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpdh8ZTFQibUKgXibwgeWziaIQ5aR5o1rfrTDibVFfribOgSWH7xb0BftEtcSg/640?wx_fmt=png&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
  
2: 免登录，免费fofa查询。  
  
3: 更新其他实用网络安全工具项目。  
  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpdteK3otAbeREv0X8OvQ0upviaCo70K0H1GAeafI193WBht7gG1suVygg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpdsbem0HHQLqa0mMZicia22Upaibwiaic9qeWia0Hojcic0085Wy2cGibrNu5QDA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpd6AZBh8wM16V78acLNTPZMbMe0ib7GM3JiaK397eDcdI4iazoS9PmMaic4g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpdp1HicWOlcw3OhPibX5eqHwYy9Nu1gN6bDpzoW64licIibZ3Zt1kBWo0icwg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVmPnkl92WqmO71diaib7qpdbAPwibeTKOhYPEacmP5u5AyfBpo5yicqiaplQic4pUGE2sfNiawCicAFo0BQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商暂未提供修复方案，请关注厂商网站及时更新  
## 8.往期回顾  
  
