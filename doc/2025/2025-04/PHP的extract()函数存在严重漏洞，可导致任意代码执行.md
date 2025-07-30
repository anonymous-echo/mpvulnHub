#  PHP的extract()函数存在严重漏洞，可导致任意代码执行   
邑安科技  邑安全   2025-04-18 03:24  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tvINqC7vPe1PJ99Mlvk6g2lyOa8PNDHUBPTibS0ZArZiawplq4Sne2eN1DGHqCtOTf4oCp3kWr8yPQ/640?wx_fmt=png&from=appmsg "")  
  
PHP 的 extract（） 函数中存在一个严重漏洞，攻击者可以触发内存损坏，从而导致跨多个 PHP 版本执行任意本机代码。  
  
该漏洞源于内存管理问题，该问题可能由涉及引用和对象析构函数的特定使用模式触发，该模式会影响所有主要 PHP 版本，包括 5.x、7.x 和 8.x。  
  
PHP 的 extract（） 函数漏洞  
  
该漏洞存在于 PHP 的 extract（） 函数中，特别是与 EXTR_REFS 标志一起使用时。  
  
此函数将数组中的变量导入到当前 symbol 表中，可以对其进行作以创建危险的内存条件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tvINqC7vPe1PJ99Mlvk6g2YXfXQuLT6Pjp6vcUn7fj0fEUIjhhBqhEnc0mu6V28YNF8ZpDTPuc9w/640?wx_fmt=png&from=appmsg "")  
  
当 extract（） 处理一个变量时，该变量是具有已定义的 __destruct（） 方法的对象，攻击者可以触发争用条件。  
  
__destruct（） 方法可以取消设置 extract（） 当前正在作的变量，从而导致：  
- PHP 5.x 版本中的 double-free 条件。  
  
- PHP 7.x 和 8.x 版本中的释放后使用漏洞。  
  
安全研究人员证明，可以可靠地利用这种内存损坏，通过重叠字符串和数组 zval 来执行任意代码，从而有效地为攻击者提供对 PHP 内存的读/写访问权限。  
  
该攻击遵循一种复杂的模式：  
- 用制作的对象触发 double-free/use-after-free。  
  
- 纵 PHP 的内存分配以创建重叠的内存结构。  
  
- 泄漏关键 PHP 内部结构（如 executor_globals）的内存地址。  
  
- 在内存中查找禁用的函数，如 system（）。  
  
- 通过覆盖内部结构来恢复已禁用函数的功能。  
  
地址空间布局随机化 （ASLR） 并不能阻止这种攻击，因为漏洞利用可以通过纵重叠的数据结构在运行时泄漏内存地址。  
  
该漏洞已由独立安全研究人员 LCFR 与 SSD Secure Disclosure 合作发现。  
  
概念验证代码  
  
触发漏洞的最小概念验证：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tvINqC7vPe1PJ99Mlvk6g2M3SrRf2deC6OUGObvZ0n9Ya5TQxDSRFMoAGo9M8l5vF5gjlicicKR95A/640?wx_fmt=png&from=appmsg "")  
  
使用 ASAN （AddressSanitizer） 进行调试时，此代码在 PHP 8.x 中生成 heap-use-after-free 错误，确认该漏洞。  
  
PHP 开发团队已通过 GitHub 安全公告 GHSA-4pwq-3fv3-gm94 解决了此问题。  
  
Web 应用程序管理员和 PHP 开发人员应该：  
- 立即更新到最新修补的 PHP 版本。  
  
- 避免将 extract（） 与用户控制的数据一起使用。  
  
- 如果必须使用 extract（），请避免使用 EXTR_REFS 标志。  
  
- 考虑实施其他应用程序级安全控制。  
  
此漏洞凸显了与 PHP 的动态功能和内存管理相关的风险。  
  
敦促开发人员审核他们对 extract（） 的使用情况，及时应用安全补丁，并遵守安全编码实践，以防止利用此类严重缺陷。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/php-extract-function-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
