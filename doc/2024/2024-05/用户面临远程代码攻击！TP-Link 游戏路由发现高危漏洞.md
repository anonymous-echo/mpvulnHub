#  用户面临远程代码攻击！TP-Link 游戏路由发现高危漏洞   
安全客  安全客   2024-05-28 17:27  
  
TP-Link Archer C5400X 游戏路由器  
被披露存在一个最高严重性安全漏洞  
，该漏洞可能通过发送特制的请求导致易受攻击的设备执行远程代码。  
  
该漏洞被标记为  
CVE-2024-5035  
，CVSS 评分为 10.0。它会影响路由器固件的所有版本，包括 1_1.1.6 及之前版本。该漏洞已在  
2024 年 5 月 24 日发布的  
1_1.1.7 版本中得到修补。  
  
德国网络安全公司 ONEKEY在周一发布的一份报告中  
表示  
：“通过成功利用此漏洞，远程未经身份验证的攻击者可以以提升的权限在设备上执行任意命令。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb7vDiavYQ5lSdYTJCbNuuocCeRtONVicr714nGld0dIMJzDKUgLnznsvtZNejqpzzibp7vuDJT6RaiaeQ/640?wx_fmt=other&from=appmsg "TP-Link 游戏路由器")  
  
该问题根源在于与射频测试“rftest”相关的二进制文件，该文件在启动时启动，并在 TCP 端口 8888、8889 和 8890 上公开网络监听器，从而允许远程未经身份验证的攻击者实现代码执行。  
  
虽然网络服务设计为仅接受以“   
wl  
 ”或“   
nvram get  
 ”开头的命令，但 ONEKEY 表示发现，可以通过在 shell 元字符（如 ; 、& 或 | ）后注入命令来轻松绕过该限制（例如“wl;id;”）。  
  
TP-Link 在 1_1.1.7 Build 20240510 版本中实施的修复通过丢弃任何包含这些特殊字符的命令来解决该漏洞。  
  
ONEKEY 表示：“TP-Link 提供无线设备配置 API 的需求似乎必须以快速或低成本的方式得到满足，最终导致他们在网络上暴露了一个据称有限的 shell，路由器内的客户端可以使用它来配置无线设备。”  
  
为了减轻此漏洞带来的风险，强烈建议用户将设备升级到版本 1_1.1.7。TP-Link 已实施修复措施，以防止通过 shell 元字符  
进行命令注入  
，从而增强受影响设备的安全状况。但是，用户必须保持警惕并积极主动，确保其设备更新到最新固件版本，以防范新出现的威胁。  
  
  
几周前，台达电子还披露了 DVW W02W2 工业以太网路由器 (   
CVE-2024-3871  
 ) 和 Ligowave 网络设备 (   
CVE-2024-4999  
 ) 的安全漏洞，这些漏洞可能允许远程攻击者以提升的权限获取远程命令执行。  
  
**参考链接：**  
https://thehackernews.com/2024/05/tp-link-gaming-router-vulnerability.html  
  
**来**  
  
**领**  
  
**資**  
  
**料**  
  
**【关键词】**  
**网络安全 专业入门 学习资料， 掌握网络安全技能！**  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4N2VUg5icoU6eUKJ14GUznZiaB5GRRWfKMn3k9mc03BRO6zB0LoPzN4UFb1vIKXwibvsEkPLy6ozj8Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
