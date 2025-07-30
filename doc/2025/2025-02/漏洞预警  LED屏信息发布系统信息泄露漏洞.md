#  漏洞预警 | LED屏信息发布系统信息泄露漏洞   
浅安  浅安安全   2025-02-12 00:06  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
星网锐捷DMB-BS LED屏信息发布系统是一套专业的数字媒体远程播放控制系统，它主要用于将各类媒体文件组合成多媒体节目，并通过网络传输到LED显示屏上进行有序的分屏或全屏播放。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUgFcdTclLpaibaNFbexjyNfW13WVYwLziaEIMWbZ9TiaEiafYFpia6MJ5o1vmcqdR9yOJKc4IjxvhtCBg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
信息泄露  
  
**影响：**  
获取敏感信息  
  
**简述：**  
星网锐捷DMB-BS LED屏信息发布系统的/dmb/out/taskexport.jsp接口处存在敏感信息泄露，未经身份验证的攻击者可以通过该漏洞获取服务器敏感信息。  
  
**0x04 影响版本**  
- LED屏信息发布系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.star-net.cn/  
  
  
  
