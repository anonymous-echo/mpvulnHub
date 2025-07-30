#  Ubuntu 默认工具 needrestart 曝出五个严重提权漏洞   
原创 DO SON  再说安全   2024-11-21 08:57  
  
2024年11月20日，Qualys 威胁研究单位 (TRU) 披露了  
NeedRestart实用程序（Ubuntu Server 安装的核心组件）中的五个严重漏洞。这些漏洞自 2014 年以来就存在，可能允许任何非特权用户获得对系统的完全控制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fkjOR3eVscbxDSooyF482Av6Iy2hHhiaF0iaNxQFEacJiaoEwud0o5mIIwnxcaicK32tCllyMYWUGW9KqoNf8A7YTg/640?wx_fmt=png&from=appmsg "")  
  
Qualys TRU 报告警告说  
：”  
任何非特权用户都可以利用这些漏洞来获得完全的 root 访问权限，而无需用户交互  
。“已识别的漏洞（分配为   
CVE-2024-48990  
、  
CVE-2024-48991  
、  
CVE-2024-48992  
、  
CVE-2024-10224  
和  
CVE-2024-11003  
）在 CVSS 等级上得分较高，其中四个漏洞的评分为 7.8 （高的）。  
  
什么是NeedRestart？  
  
NeedRestart  
是一个实用程序，用于确定系统或其服务在软件更新后是否需要重新启动，特别是在涉及共享库时。它是通过确保服务使用最新库来维护系统稳定性和安全性的关键组件。然而，0.8 版本（2014 年 4 月发布）中 Python 和 Ruby 等解释器的集成引入了可利用的漏洞。  
  
漏洞如何发挥作用  
  
这些漏洞源于NeedRestart与 Python 和 Ruby 解释器交互的方式。通过操纵环境变量或利用竞争条件，攻击者可以注入以 root 权限执行的恶意代码。在其中两个漏洞  
 CVE-2024-48990  
和  
CVE-2024-48922  
中，本地攻击者可以设置一个环境变量（PYTHONPATH 或 RUBYLIB），然后运行一个脚本来等待 NeedRestart 运行，并欺骗它使用攻击者运行任意代码的环境，”安全公告解释道  
。  
- CVE-2024-48990 和 CVE-2024-48992  
 ：利用攻击者控制的环境变量（例如  
PYTHONPATH、RUBYLIB   
）来执行任意代码。  
  
- CVE-2024-48991  
 ：检查时间使用时间 (TOCTOU) 竞争条件允许攻击者控制 Python 解释器。  
  
- CVE-2024-10224 和 CVE-2024-11003  
 ：它们协同工作，NeedRestart 将攻击者控制的输入传递到  
Module::ScanDeps  
 Perl 模块，导致以 root 权限执行任意 shell 命令。  
  
影响和补救  
  
成功利用这些漏洞可能会导致系统完全受损，从而使攻击者能够窃取数据、安装恶意软件或中断操作。Qualys TRU 已经开发了针对这些漏洞的有效利用方法，强调了修补的紧迫性。报告警告说：“虽然我们不会披露我们的漏洞，但请注意，这些漏洞很容易被利用，其他研究人员可能会在协调披露后不久发布有效的漏洞。”  
  
如何检查您是否受到影响  
  
在您的系统上，  
运行以下命令  
并将列出的版本与上表进行比较。  
- apt list –installed | grep “^\(needrestart\|libmodule-scandeps-perl\)”  
  
- apt 列表 –已安装 | grep “^\(需要重新启动\|libmodule-scandeps-perl\)”  
  
  
缓解措施  
  
最有效的缓解措施是将needrestart更新到版本 3.8，其中包括必要的修复。或者，用户可以通过添加以下行来在needrestart配置文件 ( /etc/needrestart/needrestart.conf ) 中禁用易受攻击的解释器启发式：  
```
$nrconf{interpscan} = 0;
```  
  
  
鉴于这些漏洞的严重性和漏洞的可用性，Ubuntu Server 用户立即采取行动来降低风险至关重要。应优先考虑更新需要重新启动或禁用易受攻击的功能，以保护系统免受潜在的损害。  
  
如果您觉得文章对您有所帮助，还请您关注我！  
  
  
  
  
欢迎您加群讨论：安全技术交流、HW情报分享讨论群！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fkjOR3eVscaCk1Hrx5ZSFpF9UDIUtfHvQ8b6TeMurEZFtR78CA7581ecq66D1YVLhtaHsyX4D9VbcPYB5UkZ9w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
