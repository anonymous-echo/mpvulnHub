#  Ubuntu安全限制遭突破：攻击者可利用内核漏洞提权   
 FreeBuf   2025-04-01 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
Ubuntu Linux 系统中存在三处关键安全限制绕过漏洞，允许本地攻击者提升权限并利用内核漏洞。这些漏洞影响 Ubuntu 23.10 和 24.04 LTS 系统，这些系统原本通过基于 AppArmor 的防护机制来限制命名空间滥用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibrtyCQMVIBZG8oeXaqehKibTicib0UPZcFPQaiaAcjkzlXLmcTzCHCBTOPwA8TsJeOSp1yQLMibjtF9Fg/640?wx_fmt=png&from=appmsg "")  
  
  
虽然这些漏洞本身无法直接获取完整的系统控制权，但当与需要 CAP_SYS_ADMIN 或 CAP_NET_ADMIN 等管理权限的内核漏洞结合使用时，将形成强大的攻击链。  
  
  
**Ubuntu用户命名空间绕过技术**  
  
  
  
Qualys 威胁研究部门（TRU）发布的安全公告指出，攻击者通过三种方法绕过了 Ubuntu 的用户命名空间限制机制——该机制原本用于防止非特权用户在隔离环境中获取管理权限。  
  
  
**1. 通过 aa-exec 工具绕过**  
  
****  
默认安装的 aa-exec 工具允许切换到宽松的 AppArmor 配置文件（如 trinity、chrome 或 flatpak）。攻击者可利用此工具执行 unshare 命令来创建不受限制的命名空间：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibrtyCQMVIBZG8oeXaqehKib0cOI4kwZMUxDcv1fHfmPibyYCVT4yGUDvkS7IErEcfpRS7bCcgQTiaXw/640?wx_fmt=png&from=appmsg "")  
  
  
这种方法可在命名空间内获得完整权限，从而绕过 Ubuntu 的限制机制。  
  
  
**2. 通过 Busybox 绕过**  
  
****  
默认 Busybox shell 的 AppArmor 配置文件允许不受限制地创建命名空间。攻击者可通过 Busybox 启动 shell 并执行：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibrtyCQMVIBZG8oeXaqehKibtklyMlNCtwJ8Oia9uuEYPP9H6l3r2sFMBXCIEqTfKEPUuF1XTEqRicOQ/640?wx_fmt=png&from=appmsg "")  
  
  
此方法在 Ubuntu 服务器和桌面版上均有效。  
  
  
**3. 通过 LD_PRELOAD 绕过**  
  
****  
通过向 Nautilus（GNOME 文件管理器）等受信任进程注入恶意共享库，攻击者可利用宽松的配置文件：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibrtyCQMVIBZG8oeXaqehKibYZCbeHLEh3YTAa3qmKOJplibJfMunkO9Kcf4ggDyE0DXq0U45EwvSiag/640?wx_fmt=png&from=appmsg "")  
  
  
该库会在进程中生成 shell，从而创建特权命名空间。  
  
  
这些漏洞主要影响：  
- **Ubuntu 24.04 LTS：**  
默认启用限制机制  
  
- **Ubuntu 23.10：**  
存在限制机制但需要手动激活  
  
  
用户命名空间对容器化和沙箱技术至关重要，但配置不当会暴露内核攻击面。研究人员强调，虽然这些绕过方法本身不会直接危害系统，但它们降低了利用内存损坏或竞态条件等内核漏洞的门槛。  
  
  
Canonical 承认了这些限制，但将其归类为纵深防御弱点而非关键漏洞。**缓解措施包括：**  
  
- **内核参数调整：**  
启用 kernel.apparmor_restrict_unprivileged_unconfined=1 以阻止 aa-exec 滥用：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibrtyCQMVIBZG8oeXaqehKib7L7PsKBYXrZicwkY7PGcCtlsjj2C5VcQibibQicjVnUriatmCnVkkZKGYAg/640?wx_fmt=png&from=appmsg "")  
  
- **配置文件加固：**  
禁用 Busybox 和 Nautilus 的宽松 AppArmor 配置文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibrtyCQMVIBZG8oeXaqehKibGbgzs7vpLhxXOxIV0aCticApawCVfuLdfezCTWVXQvczJ9aNOXUNrAQ/640?wx_fmt=png&from=appmsg "")  
  
- **加强 bwrap 配置：**  
为依赖 bwrap 的应用程序（如 Flatpak）实施细粒度的命名空间控制。  
  
管理员可使用 aa-status 审核配置文件，并通过标准 Ubuntu 渠道应用更新，但这些修复不会作为紧急补丁发布。  
目前，管理员必须手动应用缓解措施来保护易受攻击的系统。  
  
  
这一发现凸显了 Linux 发行版在平衡可用性与安全性方面面临的挑战。虽然 Ubuntu 的主动措施树立了行业标杆，但这些绕过漏洞表明纵深防御机制可能无意中引入复杂性。随着内核级漏洞利用的增加，对于同时重视正常运行时间和安全性的企业来说，自动化防御解决方案和快速加固实践至关重要。  
  
  
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
  
