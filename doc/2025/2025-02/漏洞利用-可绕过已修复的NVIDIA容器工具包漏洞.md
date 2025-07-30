#  漏洞利用-可绕过已修复的NVIDIA容器工具包漏洞   
原创 wolven Chan  风铃Sec   2025-02-13 15:58  
  
网络安全研究人员发现了一个现已修补的 NVIDIA 容器工具包安全漏洞的绕过方法，该漏洞可能被利用来突破容器的隔离保护，并获得对底层主机的完全访问权限。  
  
新发现的漏洞被追踪为 CVE-2025-23359（CVSS 评分：8.3）。该漏洞影响以下版本：  
- NVIDIA Container Toolkit（所有版本直至并包括 1.17.3）- 在 1.17.4 版本中已修复  
  
- NVIDIA GPU Operator（所有版本直至并包括 24.9.1）- 在 24.9.2 版本中已修复  
  
该公司在周二的一则公告中表示：“当使用默认配置时，NVIDIA Linux 容器工具包存在‘检查时到使用时’（TOCTOU）漏洞，精心制作的容器镜像可能会借此获得对宿主机文件系统的访问权限。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HlTX5WYQuIuy9frMPW8xG0icKyv5rDheNibAjlzGEZBTqwJcUfcuo9aJJZmice10g7hCeulBZnArwCRg/640?wx_fmt=png&from=appmsg "")  
  
“若该漏洞被成功利用，可能会导致代码执行、拒绝服务、权限提升、信息泄露以及数据篡改等情况。”  
  
云安全公司 Wiz 分享了该漏洞的更多技术细节，称这是另一个漏洞（CVE-2024-0132，CVSS 评分：9.0）的绕过漏洞，NVIDIA 已于 2024 年 9 月解决了该漏洞。  
  
简而言之，该漏洞使坏人能够将宿主机的根文件系统挂载到容器中，从而授予他们对所有文件的不受限制的访问权限。此外，还可以利用该访问权限启动特权容器，并通过运行时的 Unix 套接字实现对宿主机的完全控制。  
  
Wiz 的安全研究人员 Shir Tamari、Ronen Shustin 和 Andres Riancho 表示，他们对容器工具包的源代码分析发现，在挂载操作过程中使用的文件路径可以通过符号链接进行操纵，从而可以从容器外部（即根目录）挂载到   
/usr/lib64  
 中的路径。  
  
虽然通过容器逃逸获得的对宿主机文件系统的访问权限是只读的，但这一限制可以通过与 Unix 套接字交互来规避，从而生成新的特权容器并获得对文件系统的不受限制的访问权限。  
  
研究人员表示：“这种提升的访问权限还使我们能够监控网络流量、调试活动进程，并执行一系列其他宿主机级别的操作。”  
  
除了更新到最新版本外，还建议 NVIDIA 容器工具包的用户在生产环境中不要禁用“--no-cntlibs”标志。  
  
#### NVIDIA容器工具包介绍  
  
NVIDIA 容器工具包允许用户构建和运行 GPU 加速的容器。该工具包包含一个容器运行时库和实用工具，可自动配置容器以利用 NVIDIA GPU。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HlTX5WYQuIuy9frMPW8xG0icOOKpoVzGL3mXrwNkX8raDicgZ96lw8AziaAa3C8jAXlribkGEwaJ1weBg/640?wx_fmt=png&from=appmsg "")  
#### NVIDIA容器工具包地址  
```
```  
  
  
