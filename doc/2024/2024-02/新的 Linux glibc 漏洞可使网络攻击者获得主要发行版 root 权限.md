#  新的 Linux glibc 漏洞可使网络攻击者获得主要发行版 root 权限   
 网络安全应急技术国家工程中心   2024-02-26 15:04  
  
非特权攻击者可以利用 GNU C 库 (glibc) 中新披露的本地权限提升 (LPE) 漏洞，在默认配置下获得多个主要 Linux 发行版的 root 访问权限。  
  
该安全漏洞被追踪为CVE-2023-6246，是在 glibc 的 __vsyslog_internal() 函数中发现的，广泛使用的 syslog 和 vsyslog 函数调用该函数将消息写入系统消息记录器。  
  
该错误是由于2022 年 8 月在 glibc 2.37 中意外引入的基于堆的缓冲区溢出漏洞造成，后来在解决跟踪为 CVE-2022-39046 的不太严重的漏洞时向后移植到 glibc 2.36。  
  
Qualys 安全研究人员表示：“缓冲区溢出问题构成了重大威胁，因为它可能允许本地权限升级，使非特权用户能够通过对使用这些日志记录功能的应用程序，进行输入来获得完全的 root 访问权限。”  
  
尽管该漏洞需要特定的条件才能被利用（例如异常长的 argv[0] 或 openlog() ident 参数），但由于受影响的库广泛使用，以致于其影响也是巨大的。  
# 影响 Debian、Ubuntu 和 Fedora 系统  
  
在测试时，Qualys 确认 Debian 12 和 13、Ubuntu 23.04 和 23.10 以及 Fedora 37 到 39 都容易受到 CVE-2023-6246 漏洞的攻击，允许任何非特权用户在默认安装时，将权限升级到完全 root 访问权限。  
  
尽管他们的测试仅限于少数发行版，但研究人员补充说“其他发行版也可能是可利用的。”  
  
在分析 glibc 的其他潜在安全问题时，研究人员还发现了另外三个漏洞，其中两个较难利用，位于 __vsyslog_internal() 函数（CVE-2023-6779 和 CVE-2023-6780）中，第三个漏洞（ glibc 的 qsort() 函数中的内存损坏问题仍在等待 CVEID）。  
  
Qualys 威胁研究部门的产品经理表示：“最近发现的这些漏洞不仅是一个技术问题，而且是一个安全问题。”   
# Qualys 发现的其他 Linux root 升级缺陷  
  
在过去的几年里，Qualys 的研究人员发现了其他几个 Linux 安全漏洞，这些漏洞可以让攻击者完全控制未修补的 Linux 系统，即使在默认配置下也是如此。  
  
他们发现的漏洞包括 glibc 的 ld.so 动态加载器（ Looney Tunables ）中的一个缺陷、Polkit 的 pkexec 组件（称为 PwnKit）中的一个缺陷、内核文件系统层（称为 Sequoia）中的另一个缺陷以及 Sudo Unix 程序（又名Baron Samedit）中的一个缺陷。。  
  
Looney Tunables 漏洞 ( CVE-2023-4911 ) 披露几天后，概念验证 (PoC) 漏洞在网上发布，威胁分子在一个月后开始利用该漏洞窃取 Kinsing 恶意软件中的云服务提供商 (CSP) 凭据攻击。  
  
Kinsing 组织以在受感染的云系统（包括 Kubernetes、Docker API、Redis 和 Jenkins 服务器）上部署加密货币挖掘恶意软件而闻名。  
  
CISA 随后命令美国联邦机构确保其 Linux 系统免受 CVE-2023-4911 攻击，并将其添加到漏洞目录中，将其标记为“对企业构成重大风险”。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/new-linux-glibc-flaw-lets-attackers-get-root-on-major-distros/  
  
  
  
原文来源：  
嘶吼专业版  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
