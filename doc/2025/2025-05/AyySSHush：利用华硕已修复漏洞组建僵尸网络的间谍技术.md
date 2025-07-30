#  AyySSHush：利用华硕已修复漏洞组建僵尸网络的间谍技术   
会杀毒的单反狗  军哥网络安全读报   2025-05-30 01:01  
  
**导****读**  
  
  
  
威胁情报公司 GreyNoise 周三揭露了一项隐形恶意软件活动，该活动自3 月中旬以来将数千个面向互联网的华硕家庭和小型办公室路由器转变为后门节点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFNccxeYrT4iaYElvgWbcia2gSbc60qSb6WPicYrN6QZicBK6vJXicurVicw0Rg0sOj6hAH5S21E7EnQoAQ/640?wx_fmt=png&from=appmsg "")  
  
  
总部位于华盛顿的 GreyNoise 公司在与政府和行业合作伙伴协调的一份咨询报告中表示，身份不明的攻击者正在结合暴力登录、两个较旧的身份验证绕过漏洞和一个 2023 命令注入漏洞来完全控制设备，然后使用合法的配置设置来锁定该访问权限。  
  
  
其结果就是 GreyNoise 所称的“AyySSHush”，这是一个可以经受住固件升级、设备重启和大多数反恶意软件扫描的路由器网络，是未来僵尸网络或专业黑客团队中继基础设施的理想场所。  
  
  
GreyNoise 使用来自 Censys 的扫描数据估计约有 9,000 台华硕路由器被确认受到攻击。  
  
  
另外，法国安全研究公司 Sekoia 警告称，一个名为“ViciousTrap”的威胁组织入侵了超过 5,500 台边缘设备，并将其变成了蜜罐。  
  
  
Sekoia 表示，该攻击者正在监控包括 SOHO 路由器、SSL VPN、DVR 和 BMC 控制器在内的 50 多个品牌，可能是为了收集影响这些系统的漏洞和攻击数据。  
  
  
《安全周刊》消息人士称，这两项发现存在关联。  
  
  
据 GreyNoise 称，内部“Sift”异常检测引擎标记了三个不寻常的 HTTP POST 请求，这些请求针对的是公司传感器网格内完全模拟的华硕路由器。  
  
  
该公司的研究人员重建了一个攻击链，该攻击链会切换内置的 AiProtection 功能，在 TCP 端口 53282 上启用 SSH，并在非易失性存储器中植入攻击者控制的公钥。  
  
  
由于该漏洞存储在 NVRAM 中而非磁盘上，GreyNoise 发现，即使管理员修补了易受攻击的固件或重启路由器，该后门仍然存在。  
  
  
我们还发现攻击者禁用了日志记录功能以掩盖其踪迹。  
  
  
该漏洞利用链的核心是 CVE-2023-39780，这是一个命令注入漏洞，存在于华硕多条路由器产品线中，华硕已在最近的固件镜像中修复了该漏洞。  
  
  
GreyNoise 表示，攻击者首先会猜测弱凭证，或利用两个未分配的身份验证绕过技巧来访问管理端点。然后，攻击者会利用已修复的安全漏洞运行系统命令。  
  
  
GreyNoise 警告称：“此次活动中使用的策略（隐秘的初始访问、使用内置系统功能保持持久性以及小心避免检测）与高级长期行动中看到的策略一致。”  
  
  
该公司补充道：“这种间谍技术的水平表明对手资源充足、能力强大。”  
  
  
技术报告：  
  
https://www.labs.greynoise.io/grimoire/2025-03-28-ayysshush/  
  
  
新闻链接：  
  
https://www.securityweek.com/greynoise-flags-9000-asus-routers-backdoored-via-patched-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
