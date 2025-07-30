#  WordPress 插件曝出关键漏洞，导致 5 万个网站遭受 RCE 攻击   
 关键基础设施安全应急响应中心   2023-12-13 15:18  
  
Bleeping Computer 网站消息，一个安装了超过 9 万次的 WordPress 插件中存在一个严重的安全漏洞，威胁攻击者能够利用该漏洞获得远程代码执行权限，从而完全控制有漏洞的网站（该插件名为 "Backup Migration"，可帮助管理员自动将网站备份到本地存储或 Google Drive 账户上）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39xO5rfibL7qe0v4r2acq1vqlbfsv7nM7XXGbltya7JOK7OLYtRgobw5A13ZrnNibWtTetqpHof3qcw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
安全漏洞被追踪为 CVE-2023-6553，严重性评分为 9.8/10，由一个名为 Nex Team 的漏洞“猎人”团队发现。该团队发现漏洞后依据最近推出的漏洞悬赏计划，立刻向 WordPress 安全公司 Wordfence 报告了漏洞问题。  
  
据悉，CVE-2023-6553 安全漏洞主要影响 Backup Migration 1.3.6 及以下的所有插件版本，允许未经认证的威胁攻击者通过/include/backup-heart.PHP 文件注入 PHP 代码获得远程代码执行权限，从而接管目标网站。  
  
接收到漏洞通知后，Wordfence 方面表示威胁攻击者能够控制传递给 include 的值，然后利用这些值来实现远程代码执行。这使得未经身份验证的威胁攻击者可以在服务器上轻松执行代码。通过提交特制的请求，威胁攻击者还可以利用 CVE-2023-6553 安全漏洞来“包含”任意的恶意 PHP 代码，并在 WordPress 实例的安全上下文中的底层服务器上执行任意命令。  
  
威胁攻击者尝试在备份迁移插件使用的/includes/backup-heart.php 文件中的第 118 行的 BMI_INCLUDES 目录（通过将 BMI_ROOT_DIR 与 includes 字符串合并定义）中加入 bypasser.php。但是，BMI_ROOT_DIR 是通过第 62 行的 content-dir HTTP 标头定义的，因此 BMI_ROOT_DIR 依旧受到用户控制。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39xO5rfibL7qe0v4r2acq1vqqOMwySjQ7IWwu3pWpSEdVSoiaiart2oeap5liaG7O7fuHg1c12GFT3Vuw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【备份迁移漏洞代码（Wordfence）】  
  
接到通知后，数小时内就发布了安全补丁  
  
12 月 6 日，接到安全漏洞通知后，Wordfence 立刻向 BackupBliss（备份迁移插件背后的开发团队）报告了这一重大安全漏洞，开发人员在数小时后发布了补丁。  
  
坏消息是，尽管备份迁移 1.3.8 插件版本的补丁在漏洞报告发布当天就发布了，但据 WordPress.org org 下载统计显示，近 5 万个使用漏洞版本的 WordPress 网站在近一周后还是需要进行安全防护。鉴于此，安全研究人员强烈督促管理员尽快安装安全更新，以保护其网站免受潜在 CVE-2023-6553 安全漏洞的网络攻击。  
  
最近一段时间，WordPress 爆出了多起安全事件，WordPress 管理员还成为了网络钓鱼活动的目标，威胁攻击者试图利用 CVE-2023-45124 虚构漏洞的虚假 WordPress 安全公告作为诱饵，诱骗其管理员安装恶意插件。上周，WordPress  还修复了一个面向属性编程（POP）链漏洞，该漏洞允许未经授权的威胁攻击者在某些条件下（与多站点安装中的某些插件相结合时）获得任意 PHP 代码执行。  
  
**参考资料：**  
  
https://cybernews.com/news/grok-ai-chatgpt-openai-code-musk/  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1 "")  
  
  
