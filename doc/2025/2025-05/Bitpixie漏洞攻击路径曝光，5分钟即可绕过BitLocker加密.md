#  Bitpixie漏洞攻击路径曝光，5分钟即可绕过BitLocker加密   
 FreeBuf   2025-05-15 10:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic9g6mOZiaQnNf7kIKxgDT1siaNCyx80wwWn2323gXR8hoYribkSvzySuMdrVJa8WnTicu5XKBZBGfyVA/640?wx_fmt=png&from=appmsg "")  
  
  
安全研究人员近日展示了一种纯软件技术，可在无需物理工具（如螺丝刀、焊枪）或硬件破解的情况下，成功绕过微软BitLocker加密防护。  
  
  
通过利用名为Bitpixie（CVE-2023-21563）的漏洞，红队成员与攻防安全专家能够从内存中提取BitLocker卷主密钥（VMK），在5分钟内完整解密受保护的Windows设备。  
  
  
Compass Security研究员在红队评估报告中指出："该漏洞利用过程具有非侵入性，既不需要永久性设备改造，也无需获取完整磁盘映像"。  
  
### Part01  
### 两种主要攻击路径  
  
  
报告详细描述了两种基于软件的攻击路径：一种基于Linux系统，另一种基于Windows PE环境——二者均利用了存在缺陷的启动路径，以及BitLocker在缺乏预启动认证时对TPM（可信平台模块）的依赖机制。  
  
  
![BitLocker绕过技术演示](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ic9g6mOZiaQnNf7kIKxgDT1sIMpLqm45F7KeicXJrZEggZ2Y0E1qnoy7XdaLvVlaMXqZHWaJQwQBnkw/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
**Linux环境攻击（Bitpixie Linux版）**  
  
1. 通过Shift+重启组合键进入Windows恢复环境  
  
1. 通过PXE网络启动存在漏洞的Windows启动管理器  
  
1. 修改启动配置数据（BCD）强制PXE软重启  
  
1. 加载已签名的Linux引导程序（shimx64.efi）  
  
1. 链式加载GRUB引导器、Linux内核及初始化内存盘  
  
1. 使用内核模块扫描物理内存获取VMK  
  
1. 通过dislocker工具挂载含提取密钥的加密卷  
  
报告特别指出："只要设备启动时不要求输入PIN码或插入USB密钥，该攻击就能完全绕过BitLocker保护，在约5分钟内实现入侵，并可灵活融入社会工程攻击场景。"  
  
  
**Windows PE环境攻击（Bitpixie WinPE版）**  
  
  
针对阻止第三方签名组件的系统（如联想安全核心PC），攻击者可切换至Windows原生攻击路径：  
  
1. 通过修改BCD再次PXE启动Windows启动管理器  
  
1. 加载包含winload.efi、ntoskrnl.exe等微软签名组件的WinPE镜像  
  
1. 运行定制版WinPmem工具扫描内存获取VMK  
  
1. 利用VMK解密BitLocker元数据并提取可读恢复密钥  
  
研究人员解释："该攻击流仅使用微软签名的核心组件...只要设备信任微软Windows Production PCA 2011证书，所有受影响设备均可能遭入侵。"  
  
### Part02  
### 安全建议  
  
  
报告强调，虽然仅启用TPM保护的BitLocker配置为用户提供了便利，但这种设置使系统暴露于纯软件攻击之下。研究人员建议："启用预启动认证（PIN码、USB密钥或密钥文件）可有效缓解Bitpixie漏洞及各类软硬件攻击。"安全团队应立即审计所有使用BitLocker的设备，并强制启用预启动认证机制。  
  
  
**参考来源：**  
  
**BitLocker Encryption Bypassed in Minutes via Bitpixie (CVE-2023-21563) – PoC Reveals High-Risk Attack Path**  
  
https://securityonline.info/bitlocker-encryption-bypassed-in-minutes-via-bitpixie-cve-2023-21563-poc-reveals-high-risk-attack-path/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320343&idx=1&sn=4092a85b3c9cd6eea8dc0dcb48620652&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
