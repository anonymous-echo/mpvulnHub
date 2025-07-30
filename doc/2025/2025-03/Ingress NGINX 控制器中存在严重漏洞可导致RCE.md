#  Ingress NGINX 控制器中存在严重漏洞可导致RCE   
Ravie Lakshmanan  代码卫士   2025-03-25 17:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Ingress NGINX Controller (Kubernetes) 中存在五个严重漏洞，无需认证即可导致远程代码执行，可将超过6500个集群暴露在公开互联网中。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTuEndcjicQ92DOWWfKZJvps1FK8O4XuiaIl21hMnb0JpEbMIiaj7X5vtC3ItW0p5mVuz0hNNlMgm3vQ/640?wx_fmt=png&from=appmsg "")  
  
  
这些漏洞（CVE-2025-24513、CVE-2025-24514、CVE-2025-1097、CVE-2025-1098和CVE-2025-1974）的CVSS评分为9.8，被Wiz 公司命名为 “IngressNightmare”。值得注意的是，这些漏洞并不影响NGINX和NGINX Plus 的另一款ingress 控制器，即NGINX Ingress Controller。  
  
Wiz公司发布报告称，“利用这些漏洞可导致攻击者越权访问存储在 Kubernetes 集群中所有名称空间中的所有机密消息，从而可导致集群遭接管。”IngressNightmare 的核心问题在于它影响 Ingress NGINX Controller (Kubernetes) 的管理控制器组件，约43%的云环境易受这些漏洞的影响。Ingress NGINX Controller 将 NGINX 作为反向代理并加载均衡器，使其能够将集群之外的HTTP和HTTPS路由暴露到集群的服务中。  
  
该漏洞利用的事实是：部署在 Kubernetes pod 中的管理控制器可在无需认证的情况下通过网络进行访问。具体而言，攻击者通过直接向管理控制器发送一个恶意 ingress 对象（即 AdminssionReview 请求）的方式，远程注入任意NGINX 配置，从而导致在 Ingress NGINX Controller 的pod 上执行代码。  
  
Wiz 公司解释称，“管理控制器提升的权限和不受限制的网络可达性创造了一个关键的提升路径。攻击者可利用该漏洞执行任意代码并访问名称空间中的所有集群机密，从而导致集群遭完全接管。”  
  
这些漏洞概述如下：  
  
- CVE-2025-24514：auth-url 注释注入  
  
- CVE-2025-1097：auth-tls-match-cn 注释注入  
  
- CVE-2025-1098：镜像UID 注入  
  
- CVE-2025-1974：NGINX 配置代码执行  
  
  
  
在实验性的攻击场景下，威胁行动者通过使用 NGINX 的客户端主体缓冲区特性，将 AdmissionReview 请求发送到管理控制器，以共享库的形式将恶意payload 注入pod。而该请求包含之前提到的其中一个配置指令注入，它可导致共享库被加载，继而导致远程代码执行后果。  
  
Wiz 公司的云安全研究员 Hillai Ben-Sasson 提到，该攻击链主要涉及注入恶意配置，并利用它读取敏感文件和运行任意代码，从而导致攻击者滥用强Service Account，读取 Kubernetes 机密并最终导致接管集群。  
  
经过负责任的披露后，这些漏洞已在 Ingress NGINX Controller 版本1.12.1、1.11.5和1.10.7中修复。建议用户尽快更新至最新版本并确保管理webhook 端点未遭外部暴露。  
  
作为缓解措施，建议仅限制 Kubernetes API Server 访问管理控制器并在无必要的情况下临时禁用该管理控制器组件。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[F5修复BIG-IP 和 NGINX Plus 中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520531&idx=1&sn=3711327c08007954c754b1a665f4b963&scene=21#wechat_redirect)  
  
  
[NGINX 发布影响LDAP 实现的0day 缓解措施](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511319&idx=2&sn=7ce34db4fac8a3e29220748a71cf6cea&scene=21#wechat_redirect)  
  
  
[突发：俄罗斯警方突袭开源 Web 服务器 NGINX 的莫斯科代表处，拘留两名联合创始人](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491897&idx=1&sn=716a93f912c31e18addae3ea8a24e2f8&scene=21#wechat_redirect)  
  
  
[只需某些特定的Nginx + PHP-FPM 配置，即可触发PHP 远程代码执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491339&idx=1&sn=a84b1acbdc2fe1fdbc2089a844ef743b&scene=21#wechat_redirect)  
  
  
[F5 以6.7亿美金收购 NGINX](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489404&idx=3&sn=ef5661e9f10525c4b74aeaaf826f89b8&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/03/critical-ingress-nginx-controller.html  
  
  
题图：  
Pexels   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
