#  十年前的本地提权漏洞影响Ubuntu的needrestart软件   
鹏鹏同学  黑猫安全   2024-11-22 04:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce8HTN6n24T10cps8vL1KhDp9icTRDJZN1ibsWyFSnjwBygSelk8GAKktzD3OhaWQgtA9NvLGpblNaqg/640?wx_fmt=png&from=appmsg "")  
  
Qualys威胁研究单元（TRU）发现了needrestart软件包中的五个十年前的本地提权漏洞，这些漏洞可能允许本地攻击者在不需要用户交互的情况下获得root权限。needrestart软件包在Ubuntu中是一个utility，旨在确保系统稳定性在软件更新后。 当更新包特别是影响共享库或服务时，需要重新启动这些服务或整个系统以使更改生效。needrestart软件包在Ubuntu Server中是默认安装的，从版本21.04开始。  
  
这些漏洞可能是在needrestart版本0.8中引入的，该版本于2014年4月发布。这些漏洞被跟踪为CVE-2024-48990、CVE-2024-48991、CVE-2024-48992、CVE-2024-10224和CVE-2024-11003。这些漏洞的描述如下：  
  
CVE-2024-48990（CVSS评分：7.8）- 本地攻击者可以通过欺骗needrestart运行攻击者控制的PYTHONPATH环境变量来执行任意代码作为root。  
  
CVE-2024-48991（CVSS评分：7.8）- 本地攻击者可以通过赢得竞争条件和欺骗needrestart运行自己的fake Python解释器（而不是系统的真正Python解释器）来执行任意代码作为root。  
  
CVE-2024-48992（CVSS评分：7.8）- 本地攻击者可以通过欺骗needrestart运行Ruby解释器并控制RUBYLIB环境变量来执行任意代码作为root。  
  
CVE-2024-11003（CVSS评分：7.8）和CVE-2024-10224（CVSS评分：5.3）- 这些漏洞允许本地攻击者执行任意Shell命令。  
  
Qualys TRU团队已经开发了对这些漏洞的函数exploits，警告称它们是易于exploit的，并且可能很快会看到公共工作exploits。需要restart utility的漏洞允许本地用户在包安装或升级时执行任意代码，以便在需要restart作为root用户时提权。攻击者exploit这些漏洞可能获得root访问权限，从而损害系统的完整性和安全。这些漏洞的成功exploit可能会对企业造成严重风险，如未经授权的数据访问、恶意软件和操作中断，从而导致违规、不符合法规和声誉损害。立即通过软件更新或 disable漏洞以进行 mitigatation 是必要的。  
  
Qualys研究员建议在needrestart配置文件中添加一行以disable interpreter scanners：$nrconf{interpscan} = 0;以防止漏洞的exploit。  
  
