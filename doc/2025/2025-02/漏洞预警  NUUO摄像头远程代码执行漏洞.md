#  漏洞预警 | NUUO摄像头远程代码执行漏洞   
浅安  浅安安全   2025-02-27 00:03  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
NUUO摄像头是一款功能丰富、性能稳定的监控设备，适用于各种安全监控需求。它的高清录制、远程监控和智能检测等功能使得它在市场上具有较高的竞争力。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUeUzZJPicLGWLsRlC2PMC25RqyreJbh7zWBpkzkNXvQ48n9VfYCzuFOzfnJtuxV3DW7THznopcAHw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
NUUO摄像头的/handle_site_config.php接口存在远程代码执行漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- NUUO摄像头  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://nuuo.com/  
  
  
  
