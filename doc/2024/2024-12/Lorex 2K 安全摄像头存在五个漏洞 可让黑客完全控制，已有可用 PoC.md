#  Lorex 2K 安全摄像头存在五个漏洞 可让黑客完全控制，已有可用 PoC   
 独眼情报   2024-12-05 03:11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnQhEicGhSWcS40x9K5N4Sib8RcMw0JxZKtM8ej6mdxPwKdB5JV2zIvbnjuiaFydKN7X83G3MSEBKCbHg/640?wx_fmt=other&from=appmsg "")  
  
Rapid7 的最新研究揭示了 Lorex 2K 室内 Wi-Fi 安全摄像头中的一系列严重漏洞，这引起了消费者对安全的严重担忧。这些漏洞是在 2024 年 Pwn2Own IoT 竞赛期间发现的，攻击者可以利用这些漏洞入侵设备，可能访问实时信息并远程执行恶意代码。  
  
Rapid7 的发现详细说明了五个协同工作以实现远程代码执行 (RCE) 的漏洞。这些漏洞会影响设备的各个组件，分为两个阶段：  
  
第一阶段：身份验证绕过  
- CVE-2024-52544  
（严重，CVSS 9.8）：基于堆栈的缓冲区溢出。  
  
- CVE-2024-52545  
（中，CVSS 6.5）：越界堆读取。  
  
- CVE-2024-52546  
（中，CVSS 5.3）：空指针取消引用。  
  
此阶段允许攻击者利用内存泄漏并强制设备重启来重置设备的管理员密码。通过管理访问权限，攻击者可以远程控制设备。  
  
第二阶段：远程代码执行  
- CVE-2024-52547  
（高，CVSS 7.2）：已验证的基于堆栈的缓冲区溢出。  
  
- CVE-2024-52548  
（中，CVSS 6.7）：代码签名绕过，可实现任意本机代码执行。  
  
第 2 阶段允许攻击者利用管理权限以 root 访问权限执行操作系统命令，从而可能植入恶意软件并获得对设备的完全控制权。正如 Rapid7  
所解释的那样  
，  
“  
该漏洞将执行反向 shell 负载，从而为远程攻击者提供目标设备上的 root shell   
。”  
> https://www.rapid7.com/blog/post/2024/12/03/lorex-2k-indoor-wi-fi-security-camera-multiple-vulnerabilities-fixed/  
  
  
  
  
这些漏洞的影响非常严重：  
- 攻击者可以访问实时视频和音频，从而侵犯隐私。  
  
- 受到感染的设备可作为更广泛的网络攻击的入口点。  
  
Rapid7 强调，  
“有了有效的管理员凭据，攻击者可以查看设备上的实时视频和音频，或者利用 CVE-2024-52547 和 CVE-2024-52548 在目标设备上以 root 权限实现远程代码执行  
。”  
  
  
Rapid7 在其白皮书  
中对漏洞利用链提供了详细的技术分析  
，并且漏洞利用的  
源代码  
也可供查看。  
  
这些漏洞影响运行特定固件版本的各种 Lorex 型号，包括：  
<table><thead style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><th style="padding: 10px 5px;border-top-width: 1px;border-right: 0px;border-left: 0px;border-top-color: rgb(241, 241, 241);border-bottom-color: rgb(241, 241, 241);font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-family: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;text-align: center;"><span style="vertical-align: inherit;">设备</span></th><th style="padding: 10px 5px;border-top-width: 1px;border-right: 0px;border-left: 0px;border-top-color: rgb(241, 241, 241);border-bottom-color: rgb(241, 241, 241);font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-family: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;text-align: center;"><span style="vertical-align: inherit;">固件</span></th></tr></thead><tbody style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W461AS-EG</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.00LR000.0.R.210907</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W462AQ-EG</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.00LR000.0.R.210907</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W461AS</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.00LR000.0.R.210730</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W462AQ</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.00LR000.0.R.210730</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W461AS-EG S2</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.0000000.3.R.20220331</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W462AC-EG S2</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.0000000.3.R.20220331</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W461AS</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.0000000.3.R.202203</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W462AQ</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.0000000.3.R.202203</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font: inherit;vertical-align: baseline;"><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">W461ASC</span></td><td style="padding: 5px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(241, 241, 241);font: inherit;vertical-align: middle;"><span style="vertical-align: inherit;">2.800.030000000.3.R</span></td></tr></tbody></table>  
Lorex 已  
发布  
强制性固件更新 (V2.800.0000000.8.R.20241111) 来解决漏洞。用户需要通过 Lorex 应用程序安装此更新，以确保设备安全。该公司表示，  
“ Lorex Technology 致力于为我们的客户提供最高标准的保护和隐私  
。”  
  
  
Poc:  
> https://github.com/sfewer-r7/LorexExploit  
  
  
  
  
  
