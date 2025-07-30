#  Bricks WordPress网站生成器中存在RCE漏洞，黑客正在积极利用   
 网络安全应急技术国家工程中心   2024-02-21 16:29  
  
国外媒体近期披露，威胁攻击者正在积极利用 Brick Builder 中的关键远程代码执行 (RCE) 漏洞，在易受攻击的网站上执行恶意 PHP 代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibBuKIUdttRjFicHgjHBgx2TLibze92RhnkvKpgkIZOxoY1KpxD70YCGTFADBxAOpRw1eTzzNUcAI6Q/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
Bricks Builder 是一个高级 WordPress 插件，被“誉为”是创新的、社区驱动的可视化网站构建工具，拥有约 25000 个有效安装，可促进网站设计的用户友好性和定制化。  
  
2 月 10 日，一个名为 "snicco "的研究员发现了一个被追踪为 CVE-2024-25600 的安全漏洞，影响了以默认配置安装的 Brick Builder 主题。同一天，snicco 还披露了 CVE-2024-25600 安全漏洞的一些其它细节，加入了攻击演示，但没有加入漏洞利用代码。  
  
据悉，漏洞 CVE-2024-25600 是由 "prepare_query_vars_from_settings "函数中的一个 eval 函数错误调用导致的，未经身份验证的威胁攻击者可利用该函数执行任意 PHP 代码。  
  
WordPress 安全漏洞 Patchstack 平台在收到安全漏洞报告后，立刻通知了 Bricks 团队。2 月 13 日，在 发布的 1.9.6.1 版本中修复漏洞问题。值得一提的是，WordPress 公告指出，虽然没有证据能够表明 CVE-2024-25600 安全漏洞是否被威胁攻击者利用了，但还是敦促用户尽快升级到最新版本。  
  
**安全漏洞CVE-2024-25600其他详情**  
  
Patchstack 在近期发布的文章中分享了 CVE-2024-25600 安全漏洞的详细信息，此前该公司安全人员已经检测到了从 2 月 14 日开始的漏洞主动利用尝试。随后，Patchstack 进一步指出，CVE-2024-25600 安全漏洞源于通过 prepare_query_vars_from_settings 中的 eval 函数执行用户控制的输入，$php_query_raw 是从 queryEditor 构建的。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibBuKIUdttRjFicHgjHBgx2ThicPZJLpuGUBUdkBTtZtGib9ya8NkPkvXkE7YapXfrgAHAuEnJCnIQmw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
尽管在 render_element_permissions_check 中进行了 nonce 检查，但由于可公开访问的 nonces 和不充分的权限检查，允许未经验证的访问，因此可以通过用于服务器端渲染的 REST API 端点利用这一安全风险。  
  
Patchstack 方面还表示，研究人员在 CVE-2024-25600  漏洞暴露后阶段观察到威胁攻击者使用了特定的恶意软件，这些恶意软件可以禁用 Wordfence 和 Sucuri 等安全插件。  
  
以下 IP 地址与大多数攻击有关：  
  
200.251.23.57  
  
92.118.170.216  
  
103.187.5.128  
  
149.202.55.79  
  
5.252.118.211  
  
91.108.240.52  
  
Wordfence 确认了 CVE-2024-25600 安全漏洞的活跃利用状态，并报告称在过去发现了 24 次检测。因此，安全专家强烈建议 Bricks 用户立即升级到 1.9.3.1 版本。（具体方法是在 WordPress 面板中导航 "外观 > 主题 "并点击 "更新"，或从此处手动升级）  
  
**参考资料：**  
  
https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-rce-flaw-in-bricks-wordpress-site-builder/  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
