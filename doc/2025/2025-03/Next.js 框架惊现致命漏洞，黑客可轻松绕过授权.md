#  Next.js 框架惊现致命漏洞，黑客可轻松绕过授权   
看雪学苑  看雪学苑   2025-03-25 18:00  
  
最近，一个名为 CVE-2025-29927 的重大漏洞在 Next.js 开源框架中被发现，这一消息瞬间在开发界和安全领域引发了轩然大波。  
  
  
Next.js 作为一款广受欢迎的 React 框架，拥有每周超 900 万次的 npm 下载量，是众多企业构建全栈 Web 应用的首选。从 TikTok、Twitch 等社交娱乐巨头，到 Hulu、Netflix 等流媒体大咖，再到 Uber、Nike 等出行和运动品牌，Next.js 的身影无处不在，它凭借强大的功能和出色的性能，助力企业打造出高效、美观的 Web 应用。  
  
  
然而，此次被曝光的漏洞却让 Next.js 的光环黯然失色。该漏洞存在于 Next.js 的中间件组件中，这些组件在请求到达应用路由系统前运行，肩负着身份验证、授权、日志记录等重要职责。为了防止中间件无限循环触发，Next.js 设计了一个名为 'x-middleware-subrequest' 的头部，用于决定是否执行中间件函数。然而，正是这个设计被黑客盯上，他们可以手动发送包含特定值的该头部的请求，从而绕过所有安全检查，直接触达目标路径，这无疑给了黑客一扇通往系统核心的 “后门”。  
  
  
安全研究人员 Allam Rachid 和 Allam Yasser（inzo_）在深入研究中发现了这一漏洞，并公布了详细的技术分析。他们指出，这一头部及其特定值如同一把 “万能钥匙”，可轻易突破规则限制，让黑客有机可乘。  
  
  
据 Next.js 官方安全公告，该漏洞影响所有低于 15.2.3、14.2.25、13.5.9 和 12.3.5 的版本。目前，技术细节已公开，这意味着黑客可以迅速利用这一漏洞发起攻击。因此，官方强烈建议用户立即升级到最新版本，以封堵这一安全漏洞。  
  
  
不过，值得庆幸的是，该漏洞并非影响所有 Next.js 应用场景。Next.js 官方明确指出，仅使用 'next start' 并设置 'output: standalone' 的自托管版本受影响。而那些部署在 Vercel 和 Netlify 平台，或者以静态导出形式部署的应用则不受波及。此外，那些未在中间件中用于授权或安全检查，或者在应用后续流程中有其他验证机制的环境，也可免受此漏洞影响。  
  
  
对于暂时无法升级的用户，官方建议采取紧急措施，即阻止包含 'x-middleware-subrequest' 头的外部用户请求，以此来降低被攻击的风险。  
  
  
这一漏洞的曝光无疑为整个开发和安全社区敲响了警钟，再次提醒人们在追求技术发展和创新的同时，绝不能忽视安全防护的重要性。  
  
  
  
资讯来源：  
bleepingcomputer  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
