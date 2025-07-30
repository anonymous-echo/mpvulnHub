#  严重的 Erlang/OTP SSH RCE 漏洞现已公开，请立即修补   
Rhinoer  犀牛安全   2025-05-14 16:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkQ5YJHoFGVzHoiaXZ3e8hBqToeEk0BPWf35tghdU9rUP0NuZKOKLheiar9jqTq7rKQ30rFPrLdHrSg/640?wx_fmt=png&from=appmsg "")  
  
目前，针对一个严重的 Erlang/OTP SSH 漏洞（编号为 CVE-2025-32433）的公开攻击已被公开，该漏洞允许未经身份验证的攻击者在受影响的设备上远程执行代码。  
  
德国波鸿鲁尔大学的研究人员于周三披露了这一漏洞，并警告所有运行该守护进程的设备都存在漏洞。  
  
OpenWall 漏洞邮件列表上的披露信息显示：“该问题是由 SSH 协议消息处理中的一个缺陷引起的，该缺陷允许攻击者在身份验证之前发送连接协议消息。”   
  
该漏洞已在 25.3.2.10 和 26.2.4 版本中修复，但由于该平台通常用于电信基础设施、数据库和高可用性系统，因此可能不容易立即更新设备。  
  
然而，情况变得更加紧迫，因为多名网络安全研究人员私下创建了可在易受攻击的设备上实现远程代码执行的漏洞。  
  
其中包括Zero Day Initiative 的Peter Girnus和 Horizon3 的研究人员，他们表示该漏洞出奇地容易被利用。  
  
不久之后，ProDefense在 GitHub 上发布了PoC 漏洞，并在 Pastebin 上匿名发布了另一个漏洞，两者都迅速在社交媒体上分享。  
  
Girnus 向 BleepingComputer 证实，ProDefense 的 PoC 是有效的，但无法使用发布到 Pastebin 的 PoC 成功利用 Erlang/OTP SSH。  
  
既然公共漏洞已经存在，威胁行为者很快就会开始扫描易受攻击的系统并利用它们。  
  
Girnus 告诉 BleepingComputer：“SSH 是最常用的远程访问管理协议，因此我预计这种组合将在关键基础设施中得到广泛应用。”  
  
这有点令人担忧，尤其是考虑到电信公司频繁成为国家级 APT 攻击的目标，例如 Volt 和 Salt Typhoon。  
  
Girnus 是指某国政府支持的黑客组织，负责入侵边缘网络设备并入侵美国及世界各地的电信提供商。  
  
根据Girnus 分享的Shodan 查询结果，目前有超过 60 万个 IP 地址正在运行 Erlang/OTP。然而，研究人员表示，这些设备中的大多数运行的是 CouchDB，因此不会受到该漏洞的影响。  
  
Apache CouchDB 的一位代表还向 BleepingComputer 证实，CouchDB 不使用 Erlang/OTP 的 SSH 服务器或客户端功能，因此不存在漏洞。  
  
既然公共漏洞已经存在，强烈建议所有运行 Erlang OTP SSH 的设备在受到攻击者攻击之前立即升级。  
  
  
信息来源：  
BleepingComputer  
  
