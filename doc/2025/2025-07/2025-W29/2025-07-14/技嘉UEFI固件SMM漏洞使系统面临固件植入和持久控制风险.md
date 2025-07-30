> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324846&idx=3&sn=7a22c6935abca7bdf46bf166aa5bb5d8

#  技嘉UEFI固件SMM漏洞使系统面临固件植入和持久控制风险  
 FreeBuf   2025-07-14 11:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iboRVmw4QbAUKcqcIPQ0d4EMXbJjq3aVJuicl2m2hFK6ILichMWHsXRC4Ug9Uxt9r0kLLA4WM735KBw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
CERT/CC（  
美国计算机紧急事件响应小组协调中心  
）发布警告称，技嘉UEFI固件中存在多个高危漏洞，攻击者可利用这些漏洞在系统管理模式（SMM，System Management Mode）下执行任意代码。SMM是位于操作系统之下（Ring -2级别）的特权CPU环境。  
  
  
CERT/CC警告称："这些漏洞此前已通过私下披露方式解决，但在技嘉等部分OEM厂商的固件版本中仍存在易受攻击的实现。"  
  
  
**Part01**  
## SMM安全机制遭破坏  
##   
  
该问题的核心在于系统管理模式（SMM），这是一种强大的CPU模式，用于管理电源和温度控制等底层操作。它运行在系统管理内存（SMRAM）中——这是一个受保护的内存区域，只能通过系统管理中断（SMI）访问。  
  
  
这些漏洞利用了SMI处理程序，这些处理程序通过处理通信缓冲区传递的数据作为进入SMM的网关。由于对这些数据的验证不当，攻击者可破坏SMRAM或注入代码，从而导致危险的系统级入侵。  
  
  
**Part02**  
## 四大关键漏洞详情  
  
  
CERT/CC列出了影响技嘉固件的四个关键漏洞：  
- **CVE-2025-7029 (BRLY-2025-011)**  
RBX寄存器未经检查的使用使攻击者能够控制用于电源和温度配置逻辑的OcHeader和OcData指针，导致可向SMRAM任意写入数据。  
  
- **CVE-2025-7028 (BRLY-2025-010)**  
源自RBX和RCX的函数指针结构缺乏验证，使攻击者能够通过FuncBlock控制关键闪存操作。  
  
- **CVE-2025-7027 (BRLY-2025-009)**  
涉及未经验证的NVRAM变量的双重指针解引用漏洞，可将任意内容写入SMRAM。  
  
- **CVE-2025-7026 (BRLY-2025-008)**  
攻击者控制的RBX寄存器在CommandRcx0函数中被用作未经检查的指针，允许向SMRAM中攻击者指定的内存位置写入数据。  
  
每个漏洞都允许任意内存写入和潜在的固件植入，使攻击者能够获得操作系统之下的完全控制权。  
  
  
**Part03**  
## 远超操作系统层面的危害  
  
  
这些漏洞的后果远超典型的操作系统级入侵：  
- **Ring -2权限提升**  
攻击者可绕过内核级保护  
  
- **固件植入**  
攻击可跨重启和操作系统重装持续存在  
  
- **安全启动/BootGuard绕过**  
攻击者可禁用UEFI保护，使传统杀毒工具失效  
  
- **预启动执行**  
攻击可在恢复模式、睡眠状态或早期启动阶段触发——此时操作系统防御机制尚未激活  
  
CERT/CC表示："利用这些漏洞可禁用UEFI安全机制，如安全启动和英特尔BootGuard，从而实现隐秘的固件植入和对系统的持久控制。"  
  
  
**Part04**  
## 修复建议  
  
  
技嘉已发布固件更新以解决这些漏洞。受影响用户应：  
- 访问技嘉支持网站检查特定型号的固件更新  
  
- 立即应用更新，特别是暴露于本地或远程管理访问的系统  
  
- 关注其他OEM厂商，因为AMI固件通常被多家制造商重复使用  
  
**参考来源：**  
  
SMM Vulnerabilities in Gigabyte UEFI Firmware Expose Systems to Stealthy Attacks  
  
https://securityonline.info/smm-vulnerabilities-in-gigabyte-uefi-firmware-expose-systems-to-stealthy-attacks/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324737&idx=1&sn=8f0843cf1d51ac50bd1eae4a5f0e4c87&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
