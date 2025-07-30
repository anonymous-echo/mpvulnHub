> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506878&idx=1&sn=646896e03d930c8c4ed7eb5db4c3f087

#  NASA开放公开的漏洞赏金计划  
haidragon  安全狗的自我修养   2025-07-01 04:05  
  
# 官网：http://securitytech.cc/  
  
  
  
红队队员从对宇宙的好奇到漏洞赏金计划的炫耀之路  
# 🚀 简介  
  
   
  
当美国国家航空航天局（NASA）开放公开的漏洞赏金计划时，我知道我必须试试运气。经过几次深夜黑客攻击和大量的咖啡因，——砰——我终于在他们传奇的名人堂中赢得了一席之地。  
  
在这篇文章中，我将向您介绍**著名 NASA 子域名上的一个无害参数如何成为我的黄金门票**。  
> **免责声明：**仅供教育用途。未经明确许可，请勿测试系统。NASA 很棒，你的道德也应该如此。  
  
# 🚀0x01 — 侦察方法（又称深空扫描）  
1. **通过子域名枚举**  
 
```
Amass
```

、
```
Subfinder
```

证书透明度扫描（
```
crt.sh
```

），找到了约 3500 个 NASA 拥有的主机名。（有趣的是：矮行星的数量更少。）  
  
1. **技术指纹识别**  
 
```
httpx
```

和自定义 TLS 探测标记了几个 Adobe ColdFusion 2021 实例，它们在没有WAF的情况下顺利运行  
  
1. **目标选择**一台运行未经身份验证的“技术数据库”的 ColdFusion 主机看起来就像冥王星一样孤独；非常适合测试客户端问题。  
Nasa 子域名  
# 🚀 0x02 — 输入向量隔离（“先生，我可以看看您的event参数吗？”）  
  
每个内容请求都会触发一个控制器模式：  
  
/index.cfm?event=  
<  
controller  
>  
.  
<  
action  
>  
  
提供未定义的
```
event
```

值会触发详细的 ColdFusion 异常，并在 HTML 中回显该参数。翻译：**反射城市，人口 = 我的有效载荷**。  
  
  
技术数据库  
  
取样探头：  
  
/index.cfm?event=alert(1)  
  
结果：
```
alert(1)
```

出现在
```
<pre>
```

标签里。“叮”的一声就是我的漏洞雷达。  
  
  
堆栈跟踪错误  
# 🚀 0x03 — 有效载荷演变（浓缩版）  
  
将 XSS 从“hello world”升级到完全会话接管的五个有效载荷的快速时间表：  
  
  
有效载荷生成  
  
所有有效载荷都成功了，因为 ColdFusion 的错误处理程序打印了
```
event
```

没有输出编码的参数，从而允许多个解析上下文。  
  
  
Xss 已触发。  
  
  
饼干拉起来了。  
# 🚀 0x04 — 风险与影响分析（CVSS v3.1 = 8.6）  
  
— 风险与影响分析 (CVSS v3.1 = 8.6) — 风险与影响分析 (CVSS v3.1 = 8.6)  
> **会话劫持**经过身份验证的 NASA 工作人员 cookie 可能会被泄露得比你说“一小步”还快。  
> **权限提升**管理会话暴露了 ColdFusion 管理员，打开了服务器端的门。  
> ****任何具有 HTTP 客户端和恶意意图的攻击者都可以看到信息泄露研究元数据。  
  
  
CVSS 指标：AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N。  
# 🚀 0x05 — 披露时间表（从地面控制到重大漏洞）  
  
  
分类时间表  
  
美国宇航局四天的补丁更新：出色的表现（双关语）。  
  
  
美国宇航局 VDP  
# 🚀 0x06 — 防御性建议  
> **集中输出编码**利用 OWASP ESAPI 或 cfml 安全库来处理每个错误变量。  
> **内容安全策略**  
 
```
default‑src 'self'
```

使用基于随机数的内联脚本来控制失控的 JS。  
> **在生产环境中禁用详细堆栈跟踪**  
 
```
application.cfc
```

。
```
this.showdebugoutput = false
```

调试服务器用于暂存，而不是用于 cosmos。  
> **WAF 强化**启用针对 CFML 调整的 ModSecurity 核心规则集。  
  
# 🚀 0x07 — 结论（低地球轨道的经验教训）  
  
    
  
此次演习证明，即使是像反射型XSS这样常见的攻击类型，在与冗长的错误处理程序和传统框架结合使用时，也能造成巨大影响。系统性的侦察、谨慎的有效载荷调整以及快速、负责任的漏洞披露仍然是有效漏洞研究的支柱。  
  
入选名人堂固然令人欣慰，但更大的胜利在于协作安全：研究人员报告，供应商补救，用户依然受到保护。我的下一个计划是：深入研究 CFML 反序列化——因为太空或许是最后的边疆，但遗留中间件仍然是我们需要探索的领域。  
  
****  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERErMHeel1LlJg6AojUAPhYkMcQgQkjqYIXRIJBxXmHHBmGmYPDvcJJg7jhaO89IC28xujCjbwiblTQ/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
-   
- 公众号:安全狗的自我修养  
  
- vx:2207344074  
  
- http://  
gitee.com/haidragon  
  
- http://  
github.com/haidragon  
  
- bilibili:haidragonx  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
  
  
