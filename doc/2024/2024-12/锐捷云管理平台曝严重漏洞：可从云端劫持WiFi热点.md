#  锐捷云管理平台曝严重漏洞：可从云端劫持WiFi热点   
 网安百色   2024-12-27 11:40  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbQot4tey7QwvtPeflfnf1djQRccjq5yLZrjJU3OrD9pbfbKcdDN2wUpuNhK8AUrpdswD9w3YkibWw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
近日，网络安全研究人员在  
锐捷网络  
的云管理平台中发现多个严重漏洞，这些漏洞可能使攻击者全面控制网络设备，进而对企业和个人用户的网络安全构成重大威胁。  
  
  
  
**从云端入侵WiFi接入点**  
  
  
  
来自工控安全公司Claroty的研究人员NoamMoshe和Tomer Goldschmidt指出，这些漏洞不仅影响锐捷的睿易云管理平台（Reyee），还波及基于Reyee OS的网络设备。  
  
  
研究团队不仅发现了多达10个漏洞，还设计了一种名为“Open Sesame”的攻击方式，可通过云端入侵物理附近的接入点，从而未经授权访问网络。  
  
  
**在发现的10个漏洞中有三个高危漏洞，如下：**  
  
****  
CVE-2024-47547  
- 评分：9.4（高危漏洞）  
  
- 问题：  
弱密码  
恢复机制，使身份验证机制易受暴力破解攻击。  
  
CVE-2024-48874  
- 评分：9.8（高危漏洞）  
  
- 问题：服务端请求伪造（SSRF）漏洞，攻击者可利用其访问AWS云元数据服务，渗透锐捷的  
内部云  
基础设施。  
  
CVE-2024-52324  
- 评分：9.8（高危漏洞）  
  
- 问题：使用高风险功能，允许攻击者发送恶意  
MQTT  
消息，导致设备执行任意操作系统命令。  
  
  
  
  
**攻击链条与破坏潜力**  
  
  
  
Claroty研究人员指出，MQTT协议的身份验证机制存在明显弱点，只需设备序列号即可破解（CVE-2024-45722，评分：7.5）。通过这一漏洞，攻击者可以获取所有连接至云端的设备列表，并生成有效的认证凭据。这些凭据进一步被利用执行以下攻击：  
  
- 拒绝服务攻击（DoS）：通过伪造认证中断设备连接。  
  
- 发送虚假数据：在云端注入错误信息，误导设备用户。  
  
此外，攻击者还可以拦截Wi-Fi信标，提取设备序列号，从而利用MQTT漏洞实现远程代码执行。这种“OpenSesame”攻击被分配为CVE-2024-47146（评分：7.5）。  
  
  
  
**漏洞修复与影响评估**  
  
  
  
在经过负责任披露后，锐捷网络已修复了上述漏洞，并更新了相关云服务。用户无需额外操作即可确保设备安全。据估计，约5万台云连接设备可能受到影响。  
  
  
Claroty的研究人员警告，这一事件再次表明，物联网设备（IoT）中的安全弱点对网络安全构成深远威胁。尤其是  
无线接入点  
、路由器等用户门槛较低的设备，却能为攻击者提供深入网络的路径。  
  
  
参考链接：  
  
https://claroty.com/team82/research/the-insecure-iot-cloud-strikes-again-rce-on-ruijie-cloud-connected-devices  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
