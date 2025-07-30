#  安全资讯|英特尔CPU曝分支权限注入重大安全漏洞   
 SecHub网络安全社区   2025-05-16 02:22  
  
****  
****  
****  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**免责声明**  
  
本文发布的工具和脚本，仅用作测试和学习研究，禁止用于商业用途，不能保证其合法性，准确性，完整性和有效性，请根据情况自行判断。  
  
如果任何单位或个人认为该项目的脚本可能涉嫌侵犯其权利，则应及时通知并提供身份证明，所有权证明，我们将在收到认证文件后删除相关内容。  
  
文中所涉及的技术、思路及工具等相关知识仅供安全为目的的学习使用，任何人不得将其应用于非法用途及盈利等目的，间接使用文章中的任何工具、思路及技术，我方对于由此引起的法律后果概不负责。  
## 🌟简介  
##     所有现代英特尔 CPU 中存在一个名为“分支权限注入”的新漏洞，允许攻击者从分配给操作系统内核等特权软件的内存区域泄露敏感数据。  
##     通常，这些区域包含诸如密码、加密密钥、其他进程的内存和内核数据结构等信息，因此保护它们免受泄露至关重要。  
##     CVE-2024-45332，被称为分支权限注入，利用英特尔分支预测单元 BTB 和 IBP 的异步更新来跨越权限边界。当进程从用户模式转换为内核模式时，存在一个短暂的时间间隔，其中预测器状态反映用户模式训练。如果攻击者在选定的设备地址上训练了预测器，内核上下文中的推测执行将跟随该分支，执行攻击者控制的代码路径，这些路径会触及敏感的内核内存。随后，通过缓存行为的侧信道分析揭示了密码散列和加密密钥等秘密数据，在 Ubuntu 24.04 上，默认的 Spectre v2 保护下，已证明泄露速率高达 5.6 KB/s，准确率为 99.8%。  
  
**受影响的版本**  
  
CVE-2024-45332 影响从第九代开始的全部英特尔 CPU，包括 Coffee Lake、Comet Lake、Rocket Lake、Alder Lake 和 Raptor Lake。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZom34q3Z0ebsY1JY8t7P0uZbylibJV3Jeln98FMMXcVY7OdTYLaFUJgcWHdOicHa8ibtibLwGOehSQtTg/640?wx_fmt=png&from=appmsg "")  
  
**修补措施**  
  
**尽管攻击在 Linux 上进行了演示，但漏洞存在于硬件层面，因此理论上在 Windows 上也可被利用。**  
  
**英特尔发布了缓解受影响型号 CVE-2024-45332 的微代码更新。**  
  
固件级别的缓解措施引入了 2.7%的性能开销，而软件缓解措施的性能影响在 1.6%到 8.3%之间，具体取决于 CPU。  
  
    对于普通用户来说，风险较低，攻击需要多个强烈的前提条件才能打开现实的可利用场景。话虽如此，建议应用最新的 BIOS/UEFI 和操作系统更新。  
  
  
  
欢迎关注SecHub网络安全社区，SecHub网络安全社区目前邀请式注册，邀请码获取见公众号菜单【邀请码】  
  
**#**  
  
  
**企业简介**  
  
  
**赛克艾威 - 网络安全解决方案提供商**  
  
****  
       北京赛克艾威科技有限公司（简称：赛克艾威），成立于2016年9月，提供全面的安全解决方案和专业的技术服务，帮助客户保护数字资产和网络环境的安全。  
  
  
安全评估|渗透测试|漏洞扫描|安全巡检  
  
代码审计|钓鱼演练|应急响应|安全运维  
  
重大时刻安保|企业安全培训  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**联系方式**  
  
电话｜010-86460828   
  
官网｜https://sechub.com.cn  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0FW5uwU0BZtn2lmMrLPwpibCeCVbtBFDRkbFb7n7ibhPRxg20spUo9mUIiakmRYABB88Idl81IpGuXfw/640?wx_fmt=gif "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwyhlWCYDVqK38BA5dbjKkH7icWmAew7SYRA7ao1bFibialrMvmQ9ib0TBvw/640?wx_fmt=jpeg "")  
  
  
**公众号：**  
sechub安全  
  
**哔哩号：**  
SecHub官方账号  
  
  
  
