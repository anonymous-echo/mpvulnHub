#  漏洞预警 | Progress WhatsUp Gold远程代码执行漏洞   
浅安  浅安安全   2024-12-12 00:00  
  
**0x00 漏洞编号**  
- CVE-2024-8785  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
WhatsUp Gold是美国Progress Software公司开发的一款网络监控软件，可监控整个网络基础设施，迅速定位并解决网络中的问题，提高网络管理员的工作效率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SW874MUohXn367TXicEqzTqeRAgd55xeGgpsEcywy0aMvKD0x7ZicRDH939dgtf3VXf4TZJ03Vvr49Q/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-8785**  
  
**漏洞类型：**  
代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
Progress Software WhatsUp Gold在NmAPI.exe组件中存在注册表覆盖远程代码执行漏洞，由于NmAPI.exe的UpdateFailoverRegistryValues操作在处理输入数据时缺乏充分验证和授权检查，未经身份验证的远程攻击者可以通过调用位于net.tcp://<目标主机>:9643上的WCF服务接口，向NmAPI.exe发送恶意构造的请求，从而修改位于HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Ipswitch\路径下的注册表值，攻击者可通过将InstallDir更改为指向其控制的UNC路径（例如，\\<attacker-ip>\share\WhatsUp），当系统或ServiceControlManager.exe服务重启时，会从攻击者控制的路径加载恶意配置文件并执行攻击者指定的恶意可执行文件，从而实现远程代码执行。成功利用该漏洞允许攻击者绕过正常的安全机制，获得对受影响系统的完全控制权，从而可能执行任意代码、窃取敏感信息、破坏系统功能或部署持久化恶意软件。  
  
**0x04 影响版本**  
- 2023.1.0 <= Progress Software WhatsUp Gold < 2024.0.1  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.progress.com/  
  
  
  
