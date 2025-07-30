#  【安全圈】超微公司的 BMC 固件存在多个高危漏洞，目前并未发现被利用   
 安全圈   2023-10-07 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj2HU5Veb92p3p1uIbBI7bnQoicZr8XWI3AWgibHTG8A6LDsw7Ay6KWHCNHXdv2FwK32y3XX6RknlBg/640?wx_fmt=png "微信图片_20230927143622.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
     
超微（Supermicro ）底板管理控制器 (BMC) 的智能平台管理接口 (IPMI) 固件中存在多个安全漏洞，这些漏洞可能导致权限升级，并在受影响的系统上执行恶意代码。  
  
据Binarly称，从CVE-2023-40284到CVE-2023-40290，这七个漏洞的危险系数不等，可使未经认证的威胁行为者获得BMC系统的根权限。超微公司已经发布了 BMC 固件更新，以修复这些漏洞。  
  
BMC 是服务器主板上的特殊处理器，支持远程管理，使管理员能够监控温度、设置风扇速度和更新 UEFI 系统固件等硬件指标。更重要的是，即使主机操作系统离线，BMC 芯片仍可保持运行，这也使它们成为部署持久性恶意软件的有效载体。  
  
每个漏洞的简要说明如下:  
  
CVE-2023-40284、CVE-2023-40287 和 CVE-2023-40288 (CVSS 分数：9.6) ，三个跨站点脚本 (XSS) 漏洞，允许未经认证的远程攻击者在登录的 BMC 用户上下文中执行任意 JavaScript 代码。  
  
CVE-2023-40285 和 CVE-2023-40286 (CVSS 得分：8.6) ，两个跨网站脚本 (XSS) 漏洞，允许未经身份验证的远程攻击者通过毒害浏览器 cookie 或本地存储，在登录的 BMC 用户的上下文中执行任意 JavaScript 代码。  
  
CVE-2023-40289 (CVSS 得分：9.1) ， 操作系统命令注入漏洞，允许具有管理权限的用户执行恶意代码。  
  
CVE-2023-40290（CVSS 得分：8.3），一个跨站点脚本 (XSS) 漏洞，允许未经身份验证的远程攻击者在已登录 BMC 用户的上下文中执行任意 JavaScript 代码，但仅限于在 Windows 上使用 Internet Explorer 11 浏览器时。  
  
Binarly在本周发布的一份技术分析报告中称，CVE-2023-40289 漏洞必须警惕，因为它允许通过验证的攻击者获得root访问权限并完全控制BMC系统。这种权限允许在 BMC 组件重启时仍能持续攻击，并在被入侵的基础架构内横向移动，感染其他端点。  
  
其他六个漏洞，特别是CVE-2023-40284、CVE-2023-40287和CVE-2023-40288可用于为BMC IPMI软件的Web服务器组件创建一个具有管理员权限的账户。  
  
因此，攻击者可以将它们与 CVE-2023-40289 结合起来，执行命令注入并实现代码执行。攻击者可能以发送网络钓鱼电子邮件的形式，其中包含指向管理员电子邮件地址的诱杀链接，单击该链接时会触发 XSS 有效负载的执行。  
## 安全隐患  
  
尽管 Binarly 表示在 2023 年 10 月初观察到超过 70000 个暴露在互联网上的 Supermicro IPMI 网络接口实例，但目前还没有证据表明存在恶意利用这些漏洞的情况。  
  
固件安全公司进一步解释说：首先，利用暴露在互联网上的 Web 服务器组件中的漏洞，可以远程入侵 BMC 系统。然后，攻击者可以通过合法的 iKVM 远程控制 BMC 功能访问服务器的操作系统，或者用恶意固件闪烁目标系统的 UEFI，从而实现对主机操作系统的持久控制。这样，攻击者就可以在内部网络中横向动，入侵其他主机。  
  
今年早些时候，AMI MegaRAC BMC 的两个安全漏洞被曝光，如果被成功利用，威胁者可以远程控制易受攻击的服务器并部署恶意软件。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj2HU5Veb92p3p1uIbBI7bnEWOdERRhqtrSFAFy86vq0ztjryViarAY6anhJOFmRlCn4mWebDPgXkg/640?wx_fmt=png "")  
[【安全圈】数百个 GitHub 存储库注入恶意代码，安全公司呼吁用户使用新版令牌](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045975&idx=1&sn=26e7adb44fd1ea761ef0a0973f1e0749&chksm=f36e2ed7c419a7c192e9313c3c6137fdb20338a8beb14f755d4d84602f9681fdf54947240702&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj2HU5Veb92p3p1uIbBI7bnlk6Gt7CFnXib6KyCTS09ECZWMK3KFxKJv0pj1JbwaWvB8aIhH1FeRYA/640?wx_fmt=png "")  
[【安全圈】微软更新 Edge、Teams 及 Skype 软件，修复 Chromium 零日漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045975&idx=2&sn=558a7cb28bce8fd763b789ca9f814fa6&chksm=f36e2ed7c419a7c1857ab5ba5942d402de81e46c2ca296fc912801942d6f73b68383c37bb95d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj2HU5Veb92p3p1uIbBI7bn30w61u2c297WUY2ueyLql5HqAmV5Cw3K1w0BN67iazwYWBcsibl7cS8A/640?wx_fmt=png "")  
[【安全圈】Arm 发布安全公告：修复 Mali GPU 数据泄露漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045975&idx=3&sn=b3f8f211d96264d3293877df85add1b1&chksm=f36e2ed7c419a7c16025d43219bbb0b7c8882f2fde68b0737181ef948e341f68e88622e0c5ec&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj2HU5Veb92p3p1uIbBI7bnuhpQtU5IK51XeibzNuWu6ib9GYCksdnLt30CrZBjEd9JleHhSs03Ipjw/640?wx_fmt=png "")  
[【安全圈】TA866 威胁组织以鞑靼语用户为目标进行攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045975&idx=4&sn=0990c5718d187dfd767d6d68a5f1c345&chksm=f36e2ed7c419a7c112819dc791e1363fe76f8b37c1bd938975ea768fdc4e3879817c2a52f5b1&scene=21#wechat_redirect)  
  
  
  
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
  
  
