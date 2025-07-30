#  针对 Windows 注册表权限提升漏洞发布的 PoC 漏洞   
 网安百色   2025-01-06 11:32  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo4gHe4lvvYjW1Gl5pm3y0rsW6OWd7lRic148gciclZxo4Y6t3uHyJefJzs3yVoKe6T3G56OLNoq9KFQ/640?wx_fmt=jpeg&from=appmsg "")  
  
一个严重的 Windows 注册表特权提升漏洞，标识为 CVE-2024-43641。此漏洞影响各种版本的 Windows Server 2025、Windows 10 和 Windows 11，CVSS v3.1 评分为 7.8，表示严重性较高。  
  
该漏洞源于 Windows 注册表中的整数溢出或回绕，可能允许攻击者以提升的权限执行任意代码。  
  
特别容易受到攻击的是基于 x64 和 ARM64 的系统，以及一些运行 Windows 版本（从 Server 2008 到 Server 2025 和 Windows 10 到 Windows 11）的 32 位系统。  
  
这种漏洞类别的发现被称为“虚假文件不变性”（FFI），这要归功于 Gabriel Landau 最近在 BlueHat IL 2024 和 REcon Montreal 2024 上发表的研究。  
  
当代码假定文件无法修改时，就会发生 FFI，因为它们是在没有FILE_SHARE_WRITE的情况下打开的。但是，在某些情况下，即使拒绝写入共享，攻击者也可以修改文件，从而导致重复读取漏洞。  
## PoC 漏洞漏洞已发布 – CVE-2024-43641  
  
该漏洞利用了 Windows 注册表配置单元内存管理中的设计疏忽。在加载注册表配置单元期间，在特定的内存压力条件下，可以从底层介质中获取、逐出和重新读取相同的内存页。  
  
这会产生一个安全问题，即恶意 SMB 服务器可能会在两个请求中使用不同的数据进行响应，从而可能破坏内核的假设。  
  
共享 PoC 的 Google Project Zero 的 Mateusz Jurczyk 演示了使用运行 Python 脚本的基于 Linux 的 SMB 服务器来操作 hive 文件的漏洞利用。PoC 在 Windows 11 23H2 上成功运行，并安装了 2024 年 7 月的补丁。  
  
为了重现该漏洞，研究人员使用了一个测试环境，其中包含一个 Windows 11 VM（4 GB RAM）和一个运行基于 Python 的 SMB 服务器的单独 Linux VM。  
  
该漏洞涉及准备大型 Hive 文件（约 900 MB）、制造内存压力以及使用恶意 SMB 服务器在连续读取请求中替换 Hive 数据。  
  
该漏洞利用 Windows 注册表中的 bin 标头结构布局，允许攻击者在相对于任意大小的缓冲区的受控越界偏移量处将受控的位数设置为 1。这会导致强大的内存损坏原语。  
  
Microsoft 已承认该漏洞，并发布了 KB5036980 Preview，其中包含其中一个建议的修复程序。该修复程序于 KB5037771 年在 Windows 11 23H2 上正式发布，但其他平台上的测试仍有待批准。  
  
与往常一样，建议用户和系统管理员应用最新的安全更新，并对潜在的漏洞保持警惕。网络安全社区将继续监控情况，以寻找任何在野外积极利用的迹象。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
