> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458596324&idx=2&sn=9aceb4a1f80e7cd75b8c79e45465f11a

#  Linux Sudo 曝重大漏洞可提权至root并绕过主机限制，速更新！  
看雪学苑  看雪学苑   2025-07-01 09:59  
  
近日，  
广泛应用于 Linux 系统的 Sudo 实用程序被曝出存在严重安全漏洞（CVE-2025-32463），该漏洞能让任何本地无特权用户将权限提升至 root，从而获取系统最高控制权。  
  
  
这一漏洞由 Stratascale 网络研究部门（CRU）的 Rich Mirch 发现，主要影响 Sudo 版本 1.9.14 至 1.9.17。其根源在于 Sudo 中鲜少使用的 chroot 选项（-R 或 –chroot）。在 2023 年 6 月发布的 Sudo v1.9.14 中，开发者更新了 chroot 功能下的命令匹配处理代码，却意外引入了这一安全隐患。  
  
  
攻击者无需系统预先为其设定任何 Sudo 规则，仅需控制可写的不受信任路径，通过 chroot () 操作，就能让 Sudo 以 root 权限执行相关命令。当 Name Service Switch（NSS）操作被触发时，系统会从不可信环境加载 /etc/nsswitch.conf 配置，攻击者借此机会放置恶意的配置文件，指定自定义 NSS 源，使 Sudo 以 root 权限加载恶意共享对象库，进而获取 root 权限，掌控整个系统。  
  
  
这一漏洞危害极大，Ubuntu、Fedora 等主流 Linux 发行版的默认配置均受影响。从风险因素来看，只要拥有本地无特权用户账户、可写入目录访问权限，即便没有现有 Sudo 权限，仅依靠默认 Sudo 配置，攻击者就能实施攻击，在 CVSS 3.1 评分体系中，该漏洞被评定为 9.8 分的 “严重” 级别。  
  
  
目前，安全研究人员已在 Ubuntu 24.04.1（Sudo 1.9.15p5 和 1.9.16p2）及 Fedora 41 Server（Sudo 1.9.15p5）系统上验证了该漏洞。值得庆幸的是，Sudo 1.9.17p1 及更高版本已修复此问题，新版本中 chroot 选项已被弃用，存在漏洞的 pivot_root () 和 unpivot_root () 函数也被移除。在此强烈建议系统管理员立即更新 Sudo 软件包，由于此漏洞暂无其他有效解决方法，及时更新是防范风险的唯一途径。  
  
  
  
资讯来源：  
cybersecuritynews  
  
转载请注明出处和本文链接  
  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
