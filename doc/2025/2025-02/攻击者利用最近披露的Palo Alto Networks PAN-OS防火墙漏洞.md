#  攻击者利用最近披露的Palo Alto Networks PAN-OS防火墙漏洞   
鹏鹏同学  黑猫安全   2025-02-16 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicW7k9uGemdD0ZdKticF5gjYGI1icUoUib15YA0GDwibnWf6Ik1CYDzTKQH9ibiapQES4Giam8xou5QHmQUw/640?wx_fmt=png&from=appmsg "")  
  
研究人员警告称，威胁行为者正在利用Palo Alto Networks PAN-OS防火墙中最近披露的一个漏洞，该漏洞被追踪为CVE-2025-0108。  
  
Shadowserver基金会的研究人员自2024年2月13日UTC时间凌晨4点以来，在他们的蜜罐中观察到了多次CVE-2025-0108的尝试。专家表示，恶意流量源自19个IP地址，攻击者试图使用最近发布的针对该漏洞的概念验证（PoC）利用代码（除了一些创造性的例外）。  
  
自2024年2月13日UTC时间凌晨4点以来，我们的蜜罐中观察到了多次Palo Alto CVE-2025-0108的尝试，有19个源IP地址尝试使用最近发布的针对该漏洞的PoC（除了一些创造性的例外）补丁信息：https://t.co/ogULH1UgBu pic.twitter.com/CzUMjAFARF— The Shadowserver Foundation (@Shadowserver) 2025年2月14日  
  
网络安全公司GreyNoise也确认，威胁行为者试图利用该漏洞。  
  
“GreyNoise可以确认CVE-2025-0108的活跃利用。”GreyNoise表示。“依赖PAN-OS防火墙的组织应假设未打补丁的设备正在成为目标，并立即采取措施保护它们。”  
  
“Palo Alto Networks PAN-OS软件中的身份验证绕过漏洞，使具有管理Web界面网络访问权限的未认证攻击者能够绕过PAN-OS管理Web界面所需的身份验证，并调用某些PHP脚本。”Palo Alto Networks发布的公告中写道。“虽然调用这些PHP脚本不会导致远程代码执行，但可能会对PAN-OS的完整性和机密性产生负面影响。”  
  
该漏洞存在于PAN-OS管理Web界面中。网络上的未认证攻击者可以利用该漏洞绕过身份验证并调用某些PHP脚本。  
  
公司警告称，如果管理界面可以从互联网或不受信任的网络访问，无论是直接访问还是通过具有管理配置文件的数据平面接口访问，风险会更高。安全供应商建议限制对受信任的内部IP地址的访问，以最小化利用风险。  
  
以下版本修复了该漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicW7k9uGemdD0ZdKticF5gjYsKgDYGmw8sWLSKT1g3ytUvvjcWibxOr18ickicd5iaus1KsSB34mn2tN7Q/640?wx_fmt=png&from=appmsg "")  
  
网络安全公司Assetnote发现了该漏洞，并发布了该问题的详细分析。  
  
研究人员证明，攻击者可以利用该漏洞从易受攻击的设备中提取数据，包括防火墙配置。  
  
Assetnote表示，CVE-2025-0108利用了PAN-OS防火墙中URL解码不当的问题，允许攻击者绕过身份验证。问题的根本原因是Nginx和Apache处理编码路径的方式不同，导致目录遍历和未经授权的PHP脚本执行。由于Nginx禁用了某些路径的身份验证，攻击者可以在没有凭据的情况下访问PAN-OS管理界面，从而导致完全的身份验证绕过。  
  
“我们探索了一种可疑（且相当常见）的架构，其中身份验证在代理层强制执行，但请求随后通过具有不同行为的第二层传递。”Assetnote发布的报告中写道。“从根本上说，这种架构会导致诸如标头走私和路径混淆等问题，从而可能引发许多影响严重的漏洞！”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicW7k9uGemdD0ZdKticF5gjYn0nDsHadjZ3jN2MLCzxq85Lcn2aLQN59EAz8mjlMz8yAouwMseBicnQ/640?wx_fmt=png&from=appmsg "")  
  
  
