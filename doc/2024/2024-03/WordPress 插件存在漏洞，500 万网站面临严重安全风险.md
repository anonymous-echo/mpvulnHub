#  WordPress 插件存在漏洞，500 万网站面临严重安全风险   
 黑战士   2024-03-02 16:43  
  
网络安全研究人员近期发现 WordPress  LiteSpeed Cache 插件中存在一个安全漏洞，该漏洞被追踪为 CVE-2023-40000，未经身份验证的威胁攻击者可利用该漏洞获取超额权限。  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PGbmE4CTriavCSeibBX8MxaJt605R9cGOM1dX2SPIR0E43oc4sUbZZoUKaGb85dWtoTnexM1r0n7MP0dPQWYRzCg/640?wx_fmt=jpeg&from=appmsg "")  
  
>   
> LiteSpeed Cache 主要用于提高网站性能，据不完全统计已经有 500 多万安装用户。  
  
  
  
  Patchstack 研究员 Rafie Muhammad 表示，LiteSpeed Cache 插件中存在未经身份验证的全站存储的跨站脚本安全漏洞，可能允许任何未经身份验证的威胁攻击者通过执行单个 HTTP 请求，在 WordPress 网站上获取超额权限，从而获取受害者的敏感信息。  
  
  WordPress 方面指出，CVE-2023-40000 安全漏洞出现的原因是缺乏用户输入”消毒"和转义输出，安全漏洞已于 2023 年 10 月在 5.7.0.1 版本升级时得到了解决。  
  
  CVE-2023-40000 漏洞源于一个名为 update_cdn_status() 的函数，可在默认安装中重现，Muhammad指表示，由于 XSS 有效载荷被设置为了管理通知，而且管理通知可以显示在任何 wp-admin 端点上，因此任何可以访问 wp-admin 区域的用户都可以轻易触发 CVE-2023-40000 漏洞。  
## *Wordfence* *频频曝出安全漏洞*  
  
2023 年 7 月 18 日，安全暖研究人员发现拥有 500 万安装用户的 WordPress 网站数据迁移插件 All-in-One WP Migration 存在未经身份验证的访问令牌操作漏洞，攻击者可借此访问网站敏感的数据信息。好消息是，由于 All-in-One WP Migration 只在网站迁移项目中使用，通常不会在其它任何时候激活，因此在一定程度上缓解了漏洞带来的安全问题。  
> All-in-One WP Migration 是一款流行的 WordPress 网站迁移工具，适用于非技术和经验不足的用户，允许将数据库、媒体、插件和主题无缝导出到一个易于在新目的地恢复的单个存档中。  
  
  
安全漏洞被追踪为 CVE-2023-40004，允许未经身份验证的“用户”访问和操纵受影响扩展上的令牌配置，使网络攻击者将网站迁移数据转移到自身的第三方云服务账户或恢复恶意备份，一旦成功利用 CVE-2023-40004 ，导致包括用户详细信息、关键网站数据和专有信息等数据信息泄露。  
  
安全研究人员在发现安全漏洞后，立刻报告给了 ServMask ，2023 年 7 月 26 日，供应商 ServMask 发布了安全更新，为 init 函数引入了权限和非 nonce 验证。  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PGbmE4CTriavCSeibBX8MxaJt605R9cGOMm3t6x5C7nC39VZwcY7eXpO1naGlRt3X3e07JXicgicWhZ1gmoYnzX2LQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
插件供应商 ServMask 提供的各种高级扩展都包含相同的易受攻击代码片段，这些代码片段在 init 函数中缺乏权限和 nonce 验证。（该代码还存在于 Box 扩展、Google Drive 扩展、One Drive 扩展和 Dropbox 扩展中，这些扩展都是为了方便使用上述第三方平台的数据迁移过程而创建。）  
  
不久后， WordPress 又被爆出一个安装了超过 9 万次的 WordPress 插件中存在一个严重的安全漏洞，威胁攻击者能够利用该漏洞获得远程代码执行权限，从而完全控制有漏洞的网站。  
> 该插件名为 "Backup Migration"，可帮助管理员自动将网站备份到本地存储或 Google Drive 账户上  
  
  
安全漏洞被追踪为 CVE-2023-6553，严重性评分为 9.8/10，由一个名为 Nex Team 的漏洞“猎人”团队发现，主要影响 Backup Migration 1.3.6 及以下的所有插件版本。该团队发现漏洞后依据最近推出的漏洞悬赏计划，立刻向 WordPress 安全公司 Wordfence 报告了漏洞问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PGbmE4CTriavCSeibBX8MxaJt605R9cGOMWk8icu3868yib57TJGLURMPZNTGDsKsHuQeUhyDJIywibQrC0Pq9tASTg/640?wx_fmt=jpeg&from=appmsg "")  
  
接收到漏洞通知后，Wordfence 方面表示威胁攻击者能够控制传递给 include 的值，然后利用这些值来实现远程代码执行，这使得未经身份验证的威胁攻击者可以在服务器上轻松执行代码。  
  
通过提交特制的请求，威胁攻击者还可以利用 CVE-2023-6553 安全漏洞来“包含”任意的恶意 PHP 代码，并在 WordPress 实例的安全上下文中的底层服务器上执行任意命令。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PGbmE4CTriavCSeibBX8MxaJt605R9cGOMwkKbkliaZQ7Iia50gaeJWib6HVRCicxyYeJL8nqObGfUzgZia4j8xXAs8FQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
2023 年12 月 6 日，安全研究人员又发现高级 WordPress 插件 Brick Builder 中的存在关键远程代码执行 (RCE) 漏洞，威胁攻击者能够利用漏洞在易受攻击的网站上执行恶意 PHP 代码。（Brick Builder 被“誉为”是创新的、社区驱动的可视化网站构建工具，拥有约 25000 个有效安装，可促进网站设计的用户友好性和定制化。）  
  
接到安全漏洞通知后，Wordfence 立刻向 BackupBliss（备份迁移插件背后的开发团队）报告了这一重大安全漏洞，开发人员在数小时后发布了补丁。  
  
参考文章：  
> https://thehackernews.com/2024/02/wordpress-litespeed-plugin.html  
> https://www.freebuf.com/news/392761.html  
  
  
  
往期推荐  
  
[iOS系统首现木马病毒](https://mp.weixin.qq.com/s?__biz=MzUxMzQ2NTM2Nw==&mid=2247492305&idx=1&sn=050852af9686cb2895ffc8718a7a2210&chksm=f9566fa9ce21e6bfdef5469a1d56648159ae20a02bc480535a9d966ab252a3640bd3d7523428&scene=21#wechat_redirect)  
  
  
[记一次有趣的逻辑漏洞挖洞经历](https://mp.weixin.qq.com/s?__biz=MzUxMzQ2NTM2Nw==&mid=2247492294&idx=1&sn=c0274415571d8792a11d752d1a1527a8&chksm=f9566fbece21e6a8d7a6f406472294a0a165ad3e839ca7c98e96b34b6c7cb006f7e992165f88&scene=21#wechat_redirect)  
  
  
[一款好用的资产收集管理Burp插件](https://mp.weixin.qq.com/s?__biz=MzUxMzQ2NTM2Nw==&mid=2247492206&idx=1&sn=b59a8c19185ea34bf4664a4263dcda8c&chksm=f9566f16ce21e600c9fee48de4ca68f4231df261b17b8706c69aea98f0da84631dbd4f01904a&scene=21#wechat_redirect)  
  
  
[waf识别工具----WAFW00F](https://mp.weixin.qq.com/s?__biz=MzUxMzQ2NTM2Nw==&mid=2247492157&idx=1&sn=9df5ebd401a2129d0120b5d3170b8b3c&chksm=f9566f45ce21e6537286426755aff6293fd421327174fe267fe784521db058e4d6c54b5a1468&scene=21#wechat_redirect)  
  
  
[逻辑漏洞背后隐藏的刷票总结](https://mp.weixin.qq.com/s?__biz=MzUxMzQ2NTM2Nw==&mid=2247492123&idx=1&sn=4cdd366cc508a26fe5aacd3e4e17a8bd&chksm=f9566f63ce21e675d62be7519adc23cdcd27f31cbe726955fab756eccab01b2600b4b4d5f07c&scene=21#wechat_redirect)  
  
  
[大力出奇迹—从目录爆破到getshell](https://mp.weixin.qq.com/s?__biz=MzUxMzQ2NTM2Nw==&mid=2247491895&idx=1&sn=ff3aa53cc001b711658bd4a6e9ace87f&chksm=f9566c4fce21e559014741e799ea749e87f774c197e0824f798367b8b6dcb2ffc77741b45fd0&scene=21#wechat_redirect)  
  
  
  
