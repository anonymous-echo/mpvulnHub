#  漏洞预警 | 金蝶EAS任意文件写入漏洞   
浅安  浅安安全   2024-11-20 00:02  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
金蝶EAS是金蝶软件公司推出的一套企业级应用软件套件，旨在帮助企业实现全面的管理和业务流程优化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVYWeZhgoC2Sr4x2V8oP9xibkOnnlCjV0xGmialjs0TgUAh0BrpU1dAT5FvxBmQoaiaibQonYFa2FEU1Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
文件上传  
  
**影响：**  
  
  
上传恶意文件  
  
  
**简述：**  
金蝶EAS的/easportal/tools/appUtil.jsp接口存在文件上传漏洞，未经授权的攻击者可以通过特制的请求包或上传恶意的webshell文件，从而进行远程代码执行，控制服务器。  
###   
  
**0x04 影响版本**  
- 金蝶EAS  
  
**0x05****POC****状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.kingdee.com/  
  
  
  
