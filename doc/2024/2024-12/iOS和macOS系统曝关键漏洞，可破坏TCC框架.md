#  iOS和macOS系统曝关键漏洞，可破坏TCC框架   
 网安百色   2024-12-17 11:30  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
近日，苹果iOS和macOS系统中被曝光一个关键的安全漏洞，若被成功利用，可能会绕过透明度、同意和控制（TCC）框架，导致用户敏感信息被未经授权访问。漏洞编号CVE-2024-44131，存在于文件提供组件中，苹果通过在iOS 18、iPadOS 18和macOS Sequoia 15中增强符号链接的验证来修复此问题。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iczI6SxGibvHhibWTfyRLOPsicwNgJibV55oFHtQUiawOYAl43icZZ0YI1kmGSAfKGIq1kpoTxFPNeD5mMw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
TCC作为苹果设备上的一项关键安全功能，允许用户对应用程序访问敏感数据的请求进行授权或拒绝，如GPS位置、联系人和照片等。  
  
  
Jamf Threat Labs发现并报告该漏洞，该公司指出，“这种TCC绕过允许未经授权地访问文件和文件夹、健康数据、麦克风或摄像头等，而不会通知用户，这削弱了用户对iOS设备安全性的信任，并使个人数据面临风险。”  
  
  
漏洞允许恶意应用在后台运行时，拦截用户在文件应用中复制或移动文件的操作，并将它们重定向到其控制的位置。这种劫持行为利用了fileproviderd的高权限，这是一个处理与iCloud和其他第三方云  
文件管理器  
相关的文件操作的守护进程，它移动文件后可以将它们上传到远程服务器。  
  
  
Jamf进一步解释：“具体来说，当用户在后台运行恶意应用可访问的目录内使用Files.app移动或复制文件或目录时，攻击者可以操纵符号链接欺骗文件应用。新的符号链接攻击方法是，首先复制一个正常的文件，为恶意进程复制已开始的可检测信号。然后在复制过程已经开始后插入一个符号链接，有效地绕过符号链接检查。”  
  
  
因此，攻击者可以利用这种方法复制、移动甚至删除路径“/var/mobile/Library/Mobile Documents/”下的各个文件和目录，以访问与第一方和  
第三方应用  
相关的iCloud备份数据，并将它们窃取。这个漏洞的严重之处在于它完全破坏了TCC框架，并且不会向用户触发任何提示。尽管如此，可以访问的数据类型取决于执行文件操作的系统进程。  
  
  
Jamf表示：“这些漏洞的严重性取决于目标进程的权限，这揭示了对某些数据类型的访问控制执行存在差距，由于这种竞态条件，并非所有数据都可以在不发出警报的情况下提取。例如，由随机分配的UUID保护的文件夹中的数据，以及通过特定API检索的数据不受这种类型的攻击影响。”  
  
  
与此同时，苹果发布了软件更新，以修复包括  
WebKit  
中的四个漏洞在内的多个问题，这些漏洞可能导致内存损坏或进程崩溃，以及音频中的一个逻辑漏洞（CVE-2024-54529），该漏洞可能允许应用程序执行具有内核权限的任意代码。  
  
  
iPhone制造商还修复了Safari中的一个漏洞（CVE-2024-44246），该漏洞可能允许网站在启用私人中继的设备上将其添加到阅读列表时获取原始IP地址。苹果表示，它通过“改进Safari发起请求的路由”来解决这个问题。  
  
  
来源：  
FreeBuf  
  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
