> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531729&idx=3&sn=2bb8fcf23ab31e057c5ee62d76ef30f2

#  Erlang/OTP SSH 中的未经身份验证的远程代码执行  
 Ots安全   2025-07-07 08:37  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
概括  
  
Erlang/OTP SSH 服务器中发现了一个严重漏洞，可能允许攻击者执行未经身份验证的远程代码执行 (RCE)。通过利用 SSH 协议消息处理中的缺陷，恶意行为者可以未经授权访问受影响的系统，并在没有有效凭证的情况下执行任意命令。  
  
我受到影响了吗？  
  
所有运行 Erlang/OTP SSH 服务器的用户都会受到此漏洞的影响，无论底层 Erlang/OTP 版本如何。如果您的应用程序使用 Erlang/OTP SSH 库提供 SSH 访问，则假设您已受到影响。  
  
影响  
  
该漏洞允许恶意攻击者在未经身份验证的情况下，通过网络访问运行 Erlang/OTP SSH 服务器的主机来执行远程代码。这可能导致上述主机被入侵，从而允许第三方未经授权访问和操纵敏感数据，或引发拒绝服务攻击。  
  
减轻  
- 更新：建议用户更新到 OTP-27.3.3（适用于 OTP-27）、OTP-26.2.5.11（适用于 OTP-26）或 OTP-25.3.2.20（适用于 OTP-25）以缓解此问题。  
  
- 临时解决方法：在升级到固定版本之前，我们建议禁用 SSH 服务器或阻止通过防火墙规则访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadpgW1ZYPMvXDLgklwJNs52I7yYdlPSjicRMgMiaWxtXMibYlzeLQyzRl0y7E0sRicibMzECXkhKg5wrPg/640?wx_fmt=png&from=appmsg "")  
  
项目地址：  
  
https://github.com/ProDefense/CVE-2025-32433  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
