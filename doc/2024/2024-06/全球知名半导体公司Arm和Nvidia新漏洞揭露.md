#  全球知名半导体公司Arm和Nvidia新漏洞揭露   
 关键基础设施安全应急响应中心   2024-06-13 14:56  
  
全球知名的半导体公司 Arm 和 Nvidia 正在敦促客户修补其产品中一系列新的漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGogtDlviaPjF9JxicDzBw1c7BLBCWatTpDqP3ePHRzCCDiadHNkicUJLUdlUeNlicUDwITEGlOibygZZFvC9w/640?wx_fmt=png&from=appmsg "")  
  
  
总部位于英国的Arm周五警告称，其 Mali GPU 内核驱动程序（一种帮助操作系统与 Mali 图形处理器进行通信的软件）中存在一个被广泛利用的零日漏洞。  
  
该漏洞编号为CVE-2024-4610，可能导致“不当的 GPU 内存处理操作”，从而引发崩溃、数据损坏或未经授权访问敏感信息等安全问题。  
  
Arm 表示，它已经注意到有关该漏洞被广泛利用的报告，并已修复该漏洞。如果用户受到此问题的影响，该公司建议他们升级 Bifrost 和 Valhall GPU 内核驱动程序。  
  
这并不是研究人员第一次发现 Arm 的 Mali GPU 内核驱动程序中存在问题。去年 10 月，该公司表示，一个被追踪为CVE-2023-4211的安全问题可能允许黑客访问使用 Mali GPU 的设备上存储的数据。  
  
去年，GitHub 上一位名为 Man Yue Mo 的研究人员发现了Mali GPU 内核驱动程序中的一个安全漏洞，该漏洞可能使黑客能够控制 Google Pixel 6 的操作系统。该问题已于 2022 年 6 月修复。  
  
美国 GPU 设计者和制造商 Nvidia 周四还披露了其 GPU 显示驱动程序和 vGPU 软件产品中 10 个新的高危和中危漏洞。  
  
该公司表示，该漏洞编号为CVE-2024-0090，是在 Nvidia 的 Windows 和 Linux GPU 驱动程序中发现的，可能导致代码执行、拒绝服务、权限提升、信息泄露和数据篡改。  
  
Nvidia 的 Windows 版 GPU 显示驱动程序也包含一个漏洞 - CVE-2024-0089 - “可能会泄露来自以前的客户端或其他进程的信息”。  
  
另一个漏洞 ( CVE-2024-0099 ) 是在 Nvidia 的虚拟 GPU (vGPU)（允许多个虚拟机共享单个物理 GPU 的软件）中发现的，它可能导致信息泄露、数据篡改、权限升级和拒绝服务。  
  
Nvidia 并未透露这两个漏洞是否已被利用。该公司建议用户下载并安装软件更新，以保护其系统免受黑客攻击。  
  
  
  
原文来源：E安全  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
