> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI3NzMzNzE5Ng==&mid=2247490237&idx=1&sn=dfd4f48b27c1593002da37e03645a275

#  【高危漏洞预警】GeoServer未授权服务器端请求伪造(SSRF)漏洞  
cexlife  飓风网络安全   2025-06-13 15:34  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JuF3H4f2KzDKibco1S6H5k7cwUdOHMiaPUyXCx0p9V9jAibx6gG5upUX1icEf5yWm0vvwkP8Eianp0ibA/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
GeoServer存在服务器端请求伪造漏洞,若未设置代理基础URL,未经身份验证的用户可通过Demo请求端点发起服务器会执行的请求,此漏洞可用于枚举内部网络,在云实例场景下还能获取敏感数据,官方已经在新版本中修复此漏洞,建议受影响用户及时升级到安全版本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JuF3H4f2KzDKibco1S6H5kdiaQZjWddUusY8klG5OqNW0UaibY7yJBJFJ2q3xoib9xQ3wuoh1AjN8ow/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JuF3H4f2KzDKibco1S6H5kblnyIFbOxFajCbfNMzyrHDCIAoJeww2fu4LmaOc1MTBUYljKicuoWMg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JuF3H4f2KzDKibco1S6H5kpLsuH1Q6icxC7KKoChs9R6RfDNn1sibH3S8YGuFPHEtOIgUeKJiaGs97g/640?wx_fmt=png&from=appmsg "")  
  
影响版本:  
  
GeoServer GeoServer<2.24.4  
  
2.25.0<=GeoServer GeoServer<2.25.2  
  
修复建议:  
  
针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:  
  
GeoServer  GeoServer >= 2.24.4  
  
GeoServer  GeoServer >= 2.25.2  
  
下载链接:  
  
https://github.com/geoserver/geoserver/releases/tag/2.24.4  
  
https://github.com/geoserver/geoserver/releases/tag/2.25.2  
  
安装前,请确保备份所有关键数据,并按照官方指南进行操作。安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  
  
