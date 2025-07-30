#  CVE - 2025 - 29927 POC Next.js 存在严重漏洞，可导致黑客绕过授权   
 Khan安全团队   2025-05-04 09:34  
  
在 Next.js 这个开源 Web 开发框架中发现了编号为 CVE-2025-29927 的严重漏洞，该漏洞可能允许攻击者绕过授权检查，使其无需经过关键安全检查就能发送到达目标路径的请求。Next.js 是一个流行的 React 框架，在 npm 上每周下载量超 900 万次，用于构建全栈 We    b 应用程序，其中包含用于身份验证和授权的中间件组件，被前端和全栈开发人员广泛用于构建 React 的 Web 应用，TikTok、Twitch、Hulu、Netflix、Uber 和 Nike 等知名公司也在其网站或应用中使用了 Next.js 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV3r4U4kWyURlLaUmibJ7yMrYTZFzMX1MfHicgc3yotm2TEfsPS1NXu0LJuyVoQlpRS76Q8tdZiavicdYg/640?wx_fmt=png&from=appmsg "")  
## 授权绕过  
##   
  
在 Next.js 中，中间件组件在请求到达应用程序路由系统之前运行，并用于身份验证、授权、日志记录、错误处理、重定向用户、应用地理阻止或速率限制等目的。  
  
为了防止中间件重新触发自身的无限循环，Next.js 使用一个名为“x-middleware-subrequest”的标头来指示是否应应用中间件功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV3r4U4kWyURlLaUmibJ7yMrYlIDTcw2ZCdtsV30rQYOBCuhibFCwCEMnFy34z44dVpOE3HA5fBuJOLA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV3r4U4kWyURlLaUmibJ7yMrY7YdeaVAtiao67IAjPY3RqmQEj2M237VahIiaxhVXibIrgtKoPiaZqiblP1g/640?wx_fmt=png&from=appmsg "")  
  
负责处理传入请求的“runMiddleware”函数会检索该标头。如果检测到“x-middleware-subrequest”标头具有特定值，则会绕过整个中间件执行链，并将请求转发到其目的地。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV3r4U4kWyURlLaUmibJ7yMrYCHl4UKnnFM3CdvTUCAErpWWr38NqSpF6RWEW7nJqqlJTukNN4N6IIw/640?wx_fmt=png&from=appmsg "")  
  
研究人员 Allam Rachid 和 Allam Yasser（inzo_）发现攻击者能手动发送含正确值标头的请求绕过保护机制，此标头及其值如同通用密钥可覆盖规则。该漏洞影响 Next.js 15.2.3、14.2.25、13.5.9 和 12.3.5 之前的所有版本，鉴于利用细节已公开，建议用户尽快升级。Next.js 安全公告称 CVE - 2025 - 29927 仅影响使用 “next start” 和 “output: standalone” 的自托管版本，Vercel 和 Nerlify 托管及静态导出部署的应用不受影响，而使用中间件进行授权或安全检查且后期未验证的环境同样受影响，若暂时无法修补，建议阻止外部用户发送包含 “x - middleware - subrequest header” 的请求 。  
  
