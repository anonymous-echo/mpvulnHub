#  【漏洞通告】FortiOS TACACS+身份认证绕过漏洞安全风险通告   
 嘉诚安全   2025-05-19 02:03  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
FortiOS TACACS+身份认证绕过漏洞，漏洞编号为：  
CVE-2025-22252  
。  
  
  
FortiOS是Fortinet提供的操作系统，用于其安全设备（如防火墙）。FortiProxy是FortiOS的一个组件，主要用于代理服务，提供反向代理、Web应用防火墙等功能，帮助企业保护其 Web 应用免受攻击并优化网络流量。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
当TACACS+配置为使用远程TACACS+服务器进行身份验证，且该服务器使用ASCII认证时，攻击者可以绕过正常的认证机制，伪装成有效管理员，获得设备的管理员权限。该漏洞可能导致未经授权的访问，进而让攻击者完全控制设备。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
FortiOS 7.6版本影响范围 7.6.0  
  
FortiOS 7.4版本影响范围 7.4.4 ≤ FortiOS ≤ 7.4.6  
  
FortiProxy 7.6版本影响范围 7.6.0 ≤ FortiProxy ≤ 7.6.1  
  
FortiSwitchManager 7.2版本影响范围7.2.5  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
官方已发布安全更新，建议受影响用户尽快升级。  
  
FortiOS 7.6版本升级至7.6.1或更高版本  
  
FortiOS 7.4版本升级至7.4.7或更高版本  
  
FortiProxy 7.6版本升级至7.6.2或更高版本  
  
FortiSwitchManager 7.2版本升级至7.2.6或更高版本  
  
下载链接：  
  
https://docs.fortinet.com/upgrade-tool/  
  
2.临时措施  
  
使用其他认证方式  
  
config user tacacs+      
  
edit "TACACS-SERVER"          
  
set server           
  
set key           
  
set authen-type [pap, mschap, chap]          
  
set source-ip       
  
next  
  
End  
  
或者  
  
config user tacacs+      
  
edit "TACACS-SERVER"          
  
set server           
  
set key           
  
unset authen-type          
  
set source-ip       
  
nextend  
  
3.通用建议  
  
定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
  
4.参考链接  
  
https://www.fortiguard.com/psirt/FG-IR-24-472  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
