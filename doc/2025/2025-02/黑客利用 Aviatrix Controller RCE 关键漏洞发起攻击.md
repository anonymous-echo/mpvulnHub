#  黑客利用 Aviatrix Controller RCE 关键漏洞发起攻击   
Rhinoer  犀牛安全   2025-02-07 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmHhbBXfQiamrop040eReAcz8IZ1iatZoByxHcaJtLsJPUUtqUAJT0ibYnPHicZiaibicaY3QeH0l10N0Vow/640?wx_fmt=png&from=appmsg "")  
  
攻击者正在利用 Aviatrix Controller 实例中一个严重的远程命令执行漏洞（CVE-2024-50603）来安装后门和加密矿工。  
  
Aviatrix 控制器是 Aviatrix 云网络平台的一部分，可增强多云环境的网络、安全性和运营可视性。它可供企业、DevOps 团队、网络工程师、云架构师和托管服务提供商使用。  
  
CVE-2024-50603由Jakub Korepta于 2024 年 10 月 17 日发现，是由于某些 API 操作中输入清理功能使用不当导致的，允许攻击者将恶意命令注入系统级操作。  
  
这使得攻击者可以使用特制的 API 请求来实现无需身份验证的远程命令执行。  
  
该漏洞影响 Aviatrix Controller 的所有版本，从 7.x 到 7.2.4820。建议用户升级到 7.1.4191 或 7.2.4996，以解决 CVE-2024-50603 风险。  
  
在野主动开发  
  
Wiz Research 报告称，2025 年 1 月 8 日在 GitHub 上发布的概念验证 (PoC) 漏洞助长了 CVE-2024-50603 的广泛利用。  
  
黑客利用该漏洞植入 Sliver 后门，并使用 XMRig（加密劫持）进行未经授权的 Monero 加密货币挖掘。  
  
Wiz 表示，尽管只有一小部分云企业环境部署了 Aviatrix Controller，但大多数都构成了横向网络移动和权限提升的风险。  
  
Wiz 解释道：根据我们的数据，大约 3% 的云企业环境已经部署了 Aviatrix Controller”。然而，我们的数据显示，在 65% 的此类环境中，托管 Aviatrix Controller 的虚拟机具有通往管理云控制平面权限的横向移动路径。”  
  
Wiz 指出，没有证据表明攻击者进行横向移动，但他们认为攻击者利用 CVE-2024-50603 来枚举主机的云权限并探索数据泄露机会。  
  
可用修复  
  
Aviatrix建议受影响的用户升级到 Aviatrix Controller 版本 7.1.4191 或 7.2.4996，其中包含针对该漏洞的修复程序。  
  
此外，需要注意的是，如果补丁应用于 7.1.4191 或 7.2.4996 之前的版本，如果控制器后来升级到 7.1.4191 或 7.2.4996 之前的版本，或者控制器没有运行 4.16.1 或更高版本的关联 CoPilot，则必须重新应用该补丁。  
  
受影响的用户还必须确保控制器不会将端口 443 暴露给互联网，并遵循建议的控制器 IP 访问指南以最大限度地减少攻击面。  
  
  
信息来源：BleepingComputer  
  
