#  Ollama AI 基础设施工具中存在严重的RCE漏洞   
THN  代码卫士   2024-06-25 17:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQowZjMia6zWIeiby5Op0NME2Mfzevv7BcjTO7ib6JH6LAd755e3uGU6H1rBeqqqbvXWNdqQHHoMPQag/640?wx_fmt=gif&from=appmsg "")  
  
**网络安全研究员详细说明了开源人工智能 (AI) 基础设施平台 Ollama 中存在的一个现已修复的远程代码执行漏洞 (CVE-2024-37032)。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQowZjMia6zWIeiby5Op0NME2d80SZusQZMOoCKjL40MUOh4P9SR0qtoqKAllicI3OniaotzicwI6lEPxA/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞被云安全公司 Wiz 称为 “Probllama”，由研究员在2024年5月5日披露，并已在5月7日发布的版本0.1.34中修复。Ollama 是用于在Windows、Linux 和 macOS 设备上进行本地封装、部署以及运行大语言模型 (LLMs) 的服务。  
  
该漏洞的根因在于输入验证不充分导致路径遍历，使攻击者用于覆写服务器上的任意文件并最终导致远程代码执行后果。攻击者需要向 Ollama API 服务器发送特殊构造的HTTP请求才能实施成功利用。攻击者需要利用 API 端点 “/api/pull”（用于从官方注册表或私有仓库下载模型），在digest字段中包含路径遍历 payload 的恶意模型 manifest 文件。  
  
该漏洞不仅可用于损坏系统上的任意文件，还可被用于通过覆写与 dynamic linker （“id.so”）相关的配置文件，远程获得代码执行能力，包含恶意共享库并在每次执行任意程序前启动。  
  
虽然API 服务器与 localhost 绑定使Linux的默认安装很大程度上降低了远程代码执行风险，但镜像部署并非如此，因为API服务器遭公开暴露。安全研究员 Sagi Tzadik 表示，“该问题在 Docker 安装中极其严重，因为服务器以root权限运行并默认监听 ‘0.0.0.0’，从而导致该漏洞遭远程利用。”  
  
更糟糕的是，Ollama 缺乏相关认证，攻击者可利用公开可访问的服务器窃取或篡改 AI 模型并攻陷自我托管的AI引用服务器。这就要求使用中间件如认证的反向代理保护此类服务的安全。Wiz 公司表示已发现1000多个 Ollama 实例在没有任何防护的情况下托管着大量AI模型。  
  
Tzadik 表示，“CVE-2024-37032是一个易于利用的远程代码执行漏洞，影响现代AI基础设施。尽管代码库相对较新且以现代程序语言编写，但典型漏洞如路径遍历仍然是一个问题。”  
  
AI 安全公司 Protect AI 曾警告称，多种开源AI/ML工具受60多个缺陷影响，其中一些严重漏洞可导致信息泄露、受限资源遭访问、提权以及系统遭完全接管。  
  
其中最严重的漏洞是CVE-2024-22476（CVSS评分10），它是位于 Intel Neural Compressor 软件中的SQL注入漏洞，可导致攻击者从主机系统中下载任意文件。该漏洞已在2.5.0中修复。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[普遍存在的LLM幻觉扩大了软件开发的攻击面](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519204&idx=1&sn=8b889973e145d7b438fdc2609171340f&chksm=ea94ba8edde33398d0452d0d8ca3dd715d06faf2ddf0b63ef13a536f320298022b695c36082c&scene=21#wechat_redirect)  
  
  
[挖出被暴露的1500+APT令牌，破解近千家公司的LLM仓库](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518271&idx=2&sn=498e1dc2bb31e36ddbfa4c69c7593122&chksm=ea94b955dde330430a08be2022b6435807998814fbf53040e98c291ad0ffced72b267796d3b1&scene=21#wechat_redirect)  
  
  
[CISA开展首次AI网络事件响应演习](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519781&idx=2&sn=98211ba85d9f4876a22cf14e43844295&chksm=ea94bf4fdde3365939e4cc2614def1213c00d4201e2a8fb7600761b18020027d18b4a4adcfe7&scene=21#wechat_redirect)  
  
  
[PyTorch 严重漏洞可导致AI敏感数据被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519716&idx=2&sn=df8e16d464e733a183fadfc8e360cc10&chksm=ea94bc8edde335986daf0ff0d4e2bdf8751fd9df7c47d7cf2d9e614452e475a020ef01df0b6c&scene=21#wechat_redirect)  
  
  
[AI驱动安全——齐向东在2024年BCS大会的主题演讲](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519706&idx=2&sn=7a3098750d66c4a6291e485439921bbf&chksm=ea94bcb0dde335a6e0d9e1bb3a5152a60cb6b2692229059304d083375991383e071124ec9563&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/06/critical-rce-vulnerability-discovered.html  
  
  
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
  
