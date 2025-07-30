#  【安全圈】WordPress插件漏洞导致网站遭受关键文件包含攻击   
 安全圈   2025-04-13 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
网络攻击  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhlF1sHmCwZibr500dtvWOV0J6Ozcx24OVmsp5WEvQP7wTh9DTDA1wsU5oVqmntH7dkwhkzvZttx7g/640?wx_fmt=png&from=appmsg "")  
  
在InstaWP Connect WordPress 插件中发现了一个严重的安全漏洞，可能使数千个网站面临远程攻击。   
  
Wordfence 的安全研究人员发现并报告了这个严重漏洞 (CVE-2025-2636)，该漏洞允许未经身份验证的攻击者在受影响的网站上执行任意代码。该漏洞的 CVSS 评分为 9.8，为最高严重程度评级，网站管理员应立即更新。  
## InstaWP Connect插件LFI漏洞  
  
该漏洞影响 InstaWP Connect 插件的所有版本，最高版本（包括 0.1.0.85）。   
  
此本地文件包含 (LFI) 缺陷存在于插件的数据库管理功能中，可通过 instawp-database-manager 参数利用。   
  
技术分类是 CWE-73：将路径名不当限制在受限目录中（“路径遍历”）。  
  
InstaWP Connect 是一款流行的 WordPress 暂存和迁移插件，使用户能够创建一键暂存环境并执行站点迁移。   
  
该插件作为 InstaWP 的配套工具，允许用户将现有的 WordPress 网站连接到 InstaWP 平台以进行登台、开发和测试。   
  
安全研究员 Cheng Liu发现该插件在将用户输入（包括函数）传递给 PHP 之前未能正确验证用户输入。  
  
恶意行为者可以使用简单的 HTTP 请求结构来利用此漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhlF1sHmCwZibr500dtvWOV0rjxHrZ1nqO9eicVrV6cJ8Xr0A1wYY0fN1CODUBjvorIJtBjT7rm14fQ/640?wx_fmt=png&from=appmsg "")  
  
此请求可能允许攻击者在无需身份验证的情况下在服务器上包含并执行任意文件。该漏洞利用向量尤其危险，因为：  
- 无需用户身份验证  
- 可以远程执行  
- 它可能造成服务器完全被攻陷  
该漏洞的摘要如下：  
  
<table><tbody><tr><td><strong><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">风险因素</span></font></font></strong></td><td><strong><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">细节</span></font></font></strong></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">受影响的产品</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">WordPress 的 InstaWP Connect 插件（版本 &lt;= 0.1.0.85）</span></font></font></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">影响</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">– 包含并执行任意 PHP 文件 – 绕过访问控制 – 获取敏感数据 – 实现代码执行</span></font></font></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">漏洞利用前提条件</span></font></font><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><br/></span></section></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">无需身份验证；可进行远程利用</span></font></font></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVSS 3.1 评分</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">9.8（严重）</span></font></font></td></tr></tbody></table>## 对 WordPress 网站的影响  
  
该漏洞允许攻击者绕过访问控制，获取敏感数据（包括数据库凭据），并实现代码执行。 在允许上传图像或其他“安全”文件类型的情况下，攻击者可以上传伪装成合法文件的恶意 PHP 代码，然后利用 LFI 漏洞执行它们。  
  
根据 VulDB 情报，该漏洞的潜在利用价格估计在 0 至 5,000 美元之间，表明其相对容易被利用。 CVSS 向量 CVSS：3.1 确认攻击向量可通过网络访问，复杂度低，并且不需要特权或用户交互。运行 InstaWP Connect 的网站管理员应立即更新到 0.1.0.86 或更新版本，其中包含针对此漏洞的补丁。   
  
如果无法立即更新，建议暂时停用该插件，直到可以应用更新。此漏洞与 InstaWP Connect 早期版本中发现的安全问题类似，包括 0.1.0.44 和 0.1.0.38 版本中的身份验证绕过漏洞。这凸显了维护最新插件安装的重要性。  
  
WordPress 安全专家强调，这种类型的漏洞特别危险，因为它可能被完全未经身份验证的用户利用，从而可能导致整个网站受到攻击。   
  
  
   END   
  
  
阅读推荐  
  
  
[【安全圈】军工研究院保密员被判无期](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069034&idx=1&sn=255d379ee8d7c7932c4bad98af623ced&scene=21#wechat_redirect)  
  
  
  
[【安全圈】在校大学生滥用AI被抓](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069034&idx=2&sn=7ba359c368ee8d44043e1bf88bce7164&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软4月安全更新：修复125个漏洞，12个存在高利用风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069034&idx=3&sn=b2c1459405fd108b2d8796be35f685ea&scene=21#wechat_redirect)  
  
  
  
[【安全圈】美团崩了，客服回应正在修复系统](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069020&idx=1&sn=022ed79cce0b038cf559d886b23da2af&scene=21#wechat_redirect)  
  
  
  
[【安全圈】邮件攻击再升级：Microsoft Office 365 用户面临凭据窃取与恶意软件双重危机](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069020&idx=2&sn=0e35bc95a241b190fd76aeb61fd1ccfb&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
