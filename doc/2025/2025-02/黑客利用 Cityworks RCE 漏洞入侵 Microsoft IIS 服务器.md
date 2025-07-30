#  黑客利用 Cityworks RCE 漏洞入侵 Microsoft IIS 服务器   
Rhinoer  犀牛安全   2025-02-15 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdFZh7o3n7X9E3yprRSaZ1tBD8iaMB4gxic2T9lQ077q4zX4Se1jOWHFdQ/640?wx_fmt=png&from=appmsg "")  
  
软件供应商 Trimble 警告称，黑客正在利用 Cityworks 反序列化漏洞在 IIS 服务器上远程执行命令并部署 Cobalt Strike 信标以进行初始网络访问。  
  
Trimble Cityworks 是一款以地理信息系统 (GIS) 为中心的资产管理和工单管理软件，主要面向地方政府、公用事业和公共工程组织设计。  
  
该产品可帮助市政当局和基础设施机构管理公共资产、处理工作订单、办理许可和执照、资本规划和预算等。  
  
该漏洞的编号为CVE-2025-0994，是一个高严重性（CVSS v4.0 评分：8.6）反序列化问题，允许经过身份验证的用户对客户的 Microsoft Internet 信息服务 (IIS) 服务器执行 RCE 攻击。  
  
Trimble表示，已经调查了客户关于黑客利用该漏洞未经授权访问客户网络的报告，这表明攻击正在进行中。  
  
利用漏洞破坏网络  
  
美国网络安全和基础设施安全局 (CISA) 发布了一份协调咨询报告，警告客户立即保护其网络免受攻击。  
  
CVE-2025-0994 漏洞影响 15.8.9 之前的 Cityworks 版本以及 23.10 之前的 Cityworks 办公配套版本。  
  
最新版本 15.8.9 和 23.10 分别于 2025 年 1 月 28 日和 29 日发布。  
  
管理内部部署的管理员必须尽快应用安全更新，而云托管实例（CWOL）将自动接收更新。  
  
Trimble 表示，它发现一些内部部署可能具有过度特权的 IIS 身份权限，并警告这些部署不应以本地或域级管理权限运行。  
  
此外，一些部署的附件目录配置不正确。供应商建议限制附件根文件夹仅包含附件。  
  
完成所有三个操作后，客户即可恢复 Cityworks 的正常运营。  
  
尽管 CISA 尚未分享该漏洞是如何被利用的，但 Trimble 已经发布了 利用该漏洞进行攻击的危害指标。  
  
这些 IOC 表明威胁行为者部署了各种远程访问工具，包括 WinPutty 和 Cobalt Strike 信标。  
  
微软昨天还警告称，攻击者正在突破 IIS 服务器，利用在线暴露的 ASP.NET 机器密钥在 ViewState 代码注入攻击中部署恶意软件。  
  
  
信息来源：BleepingComputer  
  
