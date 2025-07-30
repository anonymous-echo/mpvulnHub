#  苹果修复 macOS 高危漏洞，被黑客利用可安装恶意内核驱动   
安世加  安世加   2025-01-14 11:00  
  
1 月 14 日消息，苹果公司在 2024 年 12 月 11 日发布的 macOS Sequoia 15.2 安全更新中，修复了存在于 System Integrity Protection（SIP）功能的漏洞，  
**微软时隔 1 个月披露了该漏洞相关细节****。**  
  
****  
该漏洞追踪编号为 CVE-2024-44243，可以绕过苹果 macOS 系统的 SIP 安全防护，通过加载第三方内核扩展程序安装恶意内核驱动程序。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/UZ1NGUYLEFj4tEzjr7C0EBW2WZQ2g9HRFxTTJKCtbcdziczSzgMZIJNBiaVPjt4JlHpR06X78Gialn4Stmn39Jgbg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**注：SIP，又称“rootless”，是 macOS 的一项安全功能，通过限制 root 用户账户在受保护区域的权限，防止恶意软件更改特定文件夹和文件。**SIP 只允许苹果签名的进程或拥有特殊授权的进程（例如苹果软件更新）修改受 macOS 保护的组件。  
  
  
该漏洞存在于处理磁盘状态保持的 Storage Kit 守护进程中。攻击者需要本地访问权限和 root 权限才能利用此漏洞，攻击复杂度低，需要用户交互。  
  
  
攻击者成功利用该漏洞，可以绕过 SIP 的 root 限制，无需物理访问即可安装 rootkit（内核驱动程序），创建持久性、无法删除的恶意软件，而且绕过透明度、同意和控制（TCC）安全检查来访问受害者数据。  
  
  
本公众号发布的文章均转载自互联网或经作者投稿授权的原创，文末已注明出处，其内容和图片版权归原网站或作者本人所有，并不代表安世加的观点，若有无意侵权或转载不当之处请联系我们处理！  
  
文章来源：（IT之家）  
  
  
  
  
安世加为出海企业提供SOC 2、ISO27001、PCI DSS、TrustE认证咨询服务（点击图片可详细查看）  
  
[](https://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540448&idx=1&sn=165f2bc3b3233827b2c601a32073aca8&scene=21#wechat_redirect)  
  
  
