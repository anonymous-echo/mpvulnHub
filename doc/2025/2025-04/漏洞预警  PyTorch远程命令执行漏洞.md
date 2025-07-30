#  漏洞预警 | PyTorch远程命令执行漏洞   
浅安  浅安安全   2025-04-28 00:01  
  
**0x00 漏洞编号**  
- # CVE-2025-32434  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
PyTorch是一个开源的深度学习框架，广泛用于机器学习和人工智能领域。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUWN6SaqXXo96MIq8cFkYjAbafENWSvh8Kf42G7YXf899TD6xOzR7WzfMfDGCljwWbZ2mcelL7QMw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-32434**  
  
**漏洞类型：**  
命令执行  
  
  
**影响：**  
  
执行任意代码  
  
**简述：**  
PyTorch存在远程命令执行漏洞，当使用torch.load函数加载模型时，特别是在参数weights_only=True被设置的情况下，攻击者可利用此漏洞执行恶意代码，从而远程控制系统。  
  
**0x04 影响版本**  
- PyTorch <=   
2.5.1  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://pytorch.org/  
  
  
  
