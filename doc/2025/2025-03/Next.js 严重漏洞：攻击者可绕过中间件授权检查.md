#  Next.js 严重漏洞：攻击者可绕过中间件授权检查   
 FreeBuf   2025-03-25 19:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39eeQMZuewlyiaqic3HGZhwQibxLdFrby7hgu72XUkiciav3ibmQHbM3fqZEkewsGDw5h6YBSZfLEiat6uhA/640?wx_fmt=png&from=appmsg "")  
  
  
Next.js React 框架近日披露了一个严重的安全漏洞，攻击者可利用该漏洞绕过授权检查，未经授权访问仅限管理员或其他高权限用户访问的敏感网页。该漏洞被标记为 CVE-2025-29927，其 CVSS 评分为 9.1（满分 10.0）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39eeQMZuewlyiaqic3HGZhwQibVkq7hicmUKUbP4IHKbbLUNlLRVxiacunbOlpy6UDY8W4jmG7K39HeSVQ/640?wx_fmt=png&from=appmsg "")  
  
  
**Next.js 框架及漏洞详情**  
  
  
  
Next.js 是一个全栈框架，通过帮助处理页面渲染、路由、性能优化和 SEO 优化等，使构建和发布 Web 应用变得更加容易。Next.js 基于 React 构建，React 是一个用于从独立、可重用的组件构建 Web 用户界面的 JavaScript 库，两者结合可快速构建生产就绪的全栈应用。  
  
  
Next.js 使用自己的中间件来处理请求、保护路由、向响应添加安全标头，并处理用户身份验证和用户重定向（例如基于地理位置、会话/授权 cookie 等）。CVE-2025-29927 漏洞允许攻击者通过向目标应用程序发送带有特制_x-middleware-subrequest标头的请求来绕过中间件安全控制。  
  
  
发现该漏洞的安全研究人员 Rachid Allam 和 Yasser Allam 解释道：“如果我们在请求中添加带有正确值的_x-middleware-subrequest标头，无论中间件的用途是什么，它都将被完全忽略，请求将通过NextResponse.next()转发，并在中间件没有任何影响的情况下完成其到达原始目的地的旅程。该标头及其值充当了允许覆盖规则的万能钥匙。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39eeQMZuewlyiaqic3HGZhwQib0mVxic5ldBUoWxItf7iafsnZSNjDOibTYUcEq7DIdy4Ru7qSSic7GryvgA/640?wx_fmt=png&from=appmsg "")  
  
  
他们私下向 Vercel 报告了该漏洞，Vercel 的开发人员于 2025 年 3 月 14 日推出了临时补丁，几天后开始发布 Next.js 框架各个分支的新修复版本。  
  
  
**影响及应对措施**  
  
  
Next.js 被包括 Twitch、Spotify、Binance、Hulu、TikTok、OpenAI 等在内的众多企业广泛使用。  
  
  
根据 Next.js 维护者的说法，该漏洞影响使用中间件的自托管 Next.js 应用程序，尤其是那些仅依赖中间件进行身份验证或安全检查的应用程序。托管在 Vercel 和 Netlify 云平台上的应用程序不受影响，部署为静态导出的应用程序也不受影响（因为中间件未执行）。  
  
  
该漏洞已在版本 12.3.5、13.5.9、14.2.25 和 15.2.3 中修复。如果无法立即升级，建议用户阻止包含x-middleware-subrequest标头的外部用户请求访问 Next.js 应用程序。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
