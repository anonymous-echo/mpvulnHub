#  【漏洞预警】MongoDB Server 证书验证不当漏洞   
cexlife  飓风网络安全   2025-04-03 18:46  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu03cu5OQ7MPibAXGHuEFMlq9jRMn85ia506dTC7Yjy2VibbDQ0eiazhPHpUCu18jMBtd40BVzcpfDShEGA/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
MongoDB Server是美国MongoDB公司的一套开源的NoSQL数据库,该数据库提供面向集合的存储、动态查询、数据复制及自动故障转移等功能,存在一个证书验证不当漏洞,该漏洞源于在特定条件下运行于Linux且启用TLS和CRL吊销状态检查时,未能检查对等证书链中中间证书的吊销状态,这可能会导致身份验证不正确,此问题还可能影响集群内身份验证。  
  
修复建议:  
  
正式防护方案:  
  
厂商已发布补丁修复漏洞,建议下载相关补丁或联系厂商获取相关支持尽快更新至安全版本。  
  
MongoDB Server 安全版本:  
  
MongoDB Server >= 5.0.31  
  
MongoDB Server >= 6.0.20  
  
MongoDB Server >= 7.0.16  
  
MongoDB Server >= 8.0.4  
  
与此同时,请做好资产自查以及预防工作,以免遭受黑客攻击。  
  
参考链接:  
  
https://jira.mongodb.org/browse/SERVER-95445  
  
  
