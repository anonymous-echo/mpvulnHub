> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247582888&idx=1&sn=02b823aa4fbe49aa681dfd78302faedf

#  新型Secure Boot漏洞允许攻击者安装引导工具包恶意软件  
胡金鱼  嘶吼专业版   2025-06-16 06:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
安全研究人员披露了一种新的Secure Boot绕过技术，编号为CVE-2025-3052，可用于关闭pc和服务器的安全性，并安装引导工具包恶意软件。  
  
这个漏洞影响了几乎所有的系统，这些系统信任 Microsoft 的 "UEFI CA 2011" 证书，基本上所有支持 Secure Boot 的硬件都受到影响。  
  
Binarly研究人员Alex Matrosov在发现一个带有微软UEFI签名证书的bios闪烁实用程序后发现了CVE-2025-3052漏洞。  
  
该实用程序最初是为坚固耐用的平板电脑设计的，但由于它与微软的UEFI证书签署，它可以在任何启用安全启动的系统上运行。  
  
进一步的调查发现，这个易受攻击的模块至少从2022年底就开始在野外传播，后来在2024年被上传到VirusTotal， Binarly在那里发现了它。  
  
Binarly于2025年2月26日向CERT/CC披露了该漏洞，现在作为微软2025年6月补丁星期二的一部分，CVE-2025-3052得到了缓解。  
  
然而，在此过程中，微软确定该漏洞影响了其他13个模块，这些模块被添加到撤销数据库中。Binarly解释说：“在分类过程中，微软确定问题并不像最初认为的那样只是一个模块，实际上是14个不同的模块。”因此，在2025年6月10日补丁星期二期间发布的更新dbx包含14个新哈希值。  
# Secure Boot绕过技术  
  
这个漏洞是由一个使用微软UEFI CA 2011证书签名的合法BIOS更新工具引起的，大多数现代使用UEFI固件的系统都信任这个证书。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29icf6ln5UOLKnqWCXzhqOCIU1uqdrSYXv0fmQnzbQLOfoZIE0QOJ2fDw1DWn5n9dUv8yebXhQQeDw/640?wx_fmt=jpeg&from=appmsg "")  
  
使用Microsoft UEFI CA 2011证书签名的易受攻击模块  
  
此实用程序读取用户可写的 NVRAM 变量（IhisiParamBuffer），但未对其进行验证。如果攻击者拥有操作系统的管理员权限，他们可以修改此变量，从而在 UEFI 启动过程中将任意数据写入内存位置。这一操作发生在操作系统甚至内核加载之前。  
  
利用这一漏洞，Binarly 制作了一个概念验证型漏洞利用程序，将用于强制执行安全启动的“gSecurity2”全局变量清零。  
  
Binarly 的报告解释道：“在我们的概念验证（PoC）中，我们选择覆盖全局变量 gSecurity2。”  
  
此变量保存指向 Security2 架构协议的指针，LoadImage 函数使用该协议来强制执行安全启动。将其设置为零，实际上是禁用了安全启动，从而允许执行任何未签名的 UEFI 模块。  
  
一旦禁用，攻击者就能安装启动恶意软件，这种恶意软件能够躲避操作系统并关闭进一步的安全功能。  
  
为修复 CVE-2025-3052，微软已将受影响模块的哈希值添加到安全启动 dbx 撤销列表中。Binarly 和微软敦促用户通过今日的安全更新立即安装更新后的 dbx 文件，以保护其设备。  
  
今日，Nikolaj Schlej 披露了另一个影响基于 Insyde H2O 的 UEFI 兼容固件的 Secure Boot 旁路漏洞。该漏洞被命名为 Hydroph0bia，并被追踪为 CVE-2025-4275。该漏洞在披露 90 天后被报告给 Insyde 并得到修复。  
  
Binarly 分享了一段视频，展示了他们的概念验证如何能够禁用安全启动，并在操作系统启动前显示一条消息提示。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/new-secure-boot-flaw-lets-attackers-install-bootkit-malware-patch-now/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29icf6ln5UOLKnqWCXzhqOCIF5cmwnFcW0qVGcWYREnRQNxwkSkG5fiaChc0u4E977OANNYosIhbictQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29icf6ln5UOLKnqWCXzhqOCIucYAhsIhbFhdEex0icj62BtkSMbTbdqr8fdiaBJ4tpo7RZMmWuqM449Q/640?wx_fmt=png&from=appmsg "")  
  
  
