#  【安全圈】针对近期 Chrome 零日漏洞的利用，Mozilla 向 Windows 用户发布紧急补丁   
 安全圈   2025-03-28 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
零日漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylg0rL5XmC2Jialtt51S4kY2xv6EmkJvOo5xpd1ibtPdgdVHSfTFicdgE4zD9HK1zibWWLqw1xRuJibnN3g/640?wx_fmt=png&from=appmsg "")  
  
Mozilla 针对 Windows 系统上的 Firefox 浏览器发布了紧急安全更新，以解决一个严重漏洞，该漏洞可能允许攻击者逃离浏览器沙盒并可能控制受影响的系统。   
  
此前不久，谷歌刚刚修复了Chrome 中一个类似的零日漏洞，该漏洞正在被广泛利用。  
  
根据 Mozilla 基金会的安全公告，该漏洞涉及 Firefox 的 IPC（进程间通信）代码中的“错误句柄”，可能导致 Windows 系统上的沙盒逃逸。   
  
在 Firefox 开发人员发现了与最近被利用的 Chrome 漏洞类似的模式后，Mozilla 研究员 Andrew McCreight 被认为是发现该漏洞的人。  
  
该公告指出： “在最近的 Chrome 沙盒逃逸（CVE-2025-2783）之后，多位Firefox 开发人员在我们的 IPC 代码中发现了类似的模式。”   
  
“受到攻击的子进程可能导致父进程返回意外的强大句柄，从而导致沙盒逃逸”。  
  
该漏洞专门影响在 Windows 操作系统上运行的 Firefox。Linux、macOS 和其他操作系统不易受到此特定漏洞的影响。  
  
浏览器沙盒是一种旨在遏制潜在恶意代码并阻止其访问敏感系统资源的安全机制。   
  
沙盒逃逸漏洞允许恶意代码突破这些限制，从而可能让攻击者访问底层操作系统。  
  
该漏洞涉及 Firefox 的 IPC 机制，该机制管理浏览器不同进程组件之间的通信。   
  
该漏洞可能允许受感染的子进程诱骗父进程返回具有提升权限的句柄，从而有效绕过沙盒保护。  
  
该漏洞的摘要如下：  
  
<table><tbody><tr><td data-colwidth="289"><strong><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">风险因素</span></font></font></strong></td><td><strong><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">细节</span></font></font></strong></td></tr><tr><td data-colwidth="289"><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">受影响的产品</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">– 136.0.4 之前的 Firefox 版本 - 128.8.1 之前的 Firefox ESR 版本 - 115.21.1 之前的 Firefox ESR 版本（仅限 Windows 版本）</span></font></font></td></tr><tr><td data-colwidth="289"><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">影响</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">潜在的系统危害</span></font></font></td></tr><tr><td data-colwidth="289"><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">漏洞利用前提条件</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">– Windows 操作系统- 未修补的 Firefox 版本- 攻击者能够破坏子进程</span></font></font></td></tr><tr><td data-colwidth="289"><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVSS 3.1 分数</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">高的</span></font></font></td></tr></tbody></table>## 受影响的版本和补丁可用性  
  
Mozilla 已针对以下浏览器版本中的漏洞发布了修复程序：  
- Firefox 136.0.4  
- Firefox ESR（扩展支持版本）128.8.1  
- Firefox ESR 115.21.1  
由于该漏洞的潜在影响以及攻击者正在积极利用 Chrome 中的类似漏洞，该漏洞被列为“严重”。   
  
尽管 Mozilla 尚未确认 Firefox 漏洞是否已被广泛利用，但该公告指出“原始漏洞已被广泛利用”，很可能指的是 Chrome 零日漏洞。  
  
运行 Firefox 的 Windows 用户应立即将其浏览器更新至修补版本。   
  
自动更新通常默认启用，但用户可以通过点击菜单按钮，选择“帮助”，然后选择“关于 Firefox”来手动检查更新。浏览器将自动检查并安装任何可用的更新。  
  
这一事件凸显了  
浏览器供应商面临的持续安全挑战以及快速响应零日漏洞的重要性，尤其是当不同浏览器存在类似漏洞时。   
  
来源：  
https://cybersecuritynews.com/mozilla-releases-urgent-patch-for-windows-users/  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】Telegram惊现公开群组聊天索引机器人 抓取8.6亿名用户的560亿条发言记录](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068752&idx=1&sn=3ed6af9ca6424f9ff2aaed8978db21bb&scene=21#wechat_redirect)  
  
  
  
[【安全圈】YouTube 创作者因品牌合作者请求使用 Clickflix 技术而遭受攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068752&idx=2&sn=7bf7b957b9a03294c4dca0b72e1fccf9&scene=21#wechat_redirect)  
  
  
  
[【安全圈】恶意 npm 包修改本地 ethers 库以发起反向 Shell 攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068752&idx=3&sn=8a75b78dd7bc98c8a5cd08e216afb5c6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】新型 npm 恶意软件对热门以太坊库发动后门感染攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068752&idx=4&sn=bc2bbd031c4a9a33968bd04bac1a8ed4&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
