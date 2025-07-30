> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1OTA1MzQzNA==&mid=2651248187&idx=1&sn=05b3d6df2887f37dcac8d7e1595e2c22

#  微软云身份曝严重漏洞：对低级别用户授权致客户VPN密钥泄露、联想Windows目录可写文件漏洞可隐秘绕过AppLocker防护  
e安在线  e安在线   2025-07-07 02:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# 微软云身份曝严重漏洞：对低级别用户过度授权，导致客户VPN密钥泄露  
  
7月4日消息，以色列身份安全厂商Token Security安全专家近期开展了一项深入调查，揭示微软Azure云平台RBAC（基于角色的访问控制）架构中存在严重安全漏洞。  
  
Azure RBAC是该云平台权限管理的核心机制，允许管理员根据不同的范围（从整个订阅到具体资源）为用户、用户组或服务主体分配具有预定义权限的角色。  
  
然而调查发现，多个原本设计用于提供受限、特定服务访问权限的内置角色存在配置错误，其实际权限远远超出设定范围。  
  
包括“托管应用读取”和“日志分析读取”在内，有10个角色被错误地授予了过于宽泛的*/read权限，实际上等同于通用的“读取者”（Reader）角色。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaUMDR1XduaO0anMicbse5UqDsoqTar4ZkBAD1TehdFPUnXvmqLFicTMjQynl1KznM15mONicF74QsVQ/640?wx_fmt=jpeg "")  
  
图：角色分配  
  
这一问题导致用户能够访问所有Azure资源的敏感元数据，权限范围远超这些角色描述所设定的界限。  
  
权限的过度授予可能使攻击者得以从自动化账户中提取凭证、绘制网络配置图以辅助后续攻击，并在存储账户或备份保管库中发现关键数据，为权限提升和攻击部署创造有利条件。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaUMDR1XduaO0anMicbse5UqsIW4D0iaHppZgZ2YfFU6KlGNs20ryibuoGgHah8MnEyiapLOWagnUOm0Q/640?wx_fmt=jpeg "")  
  
图：过度授权的三类滥用方式，包括敏感数据发现、凭据窃取、攻击规划  
  
  
**利用Azure API泄露VPN预共享密钥**  
  
  
更严重的是，研究人员还发现Azure API中存在一个关键漏洞，仅凭读取权限即可泄露VPN网关的预共享密钥（PSK）。  
  
通常，Azure通过HTTP方法区分权限控制。只读操作使用GET，而访问敏感数据则需通过POST请求，以防止未经授权的访问。  
  
然而，由于API设计上的疏漏，VPN连接的共享密钥竟被设置为通过GET请求获取，从而绕过了应有的安全防护机制。  
  
这一漏洞使得攻击者即便仅拥有最低级别的读取权限（通常由上述过度授权的角色授予），也能够获取站点到站点（S2S）VPN连接的PSK。  
  
一旦获取该密钥，恶意行为者便可建立恶意连接，进而未经授权地访问内部云资源、虚拟私有云（VPC）乃至通过Azure VPN网关连接的本地网络。  
  
这一漏洞将本应无害的读取权限转变为入侵网络的入口。在云与本地系统深度融合的混合环境中，其后果尤为严重。  
  
  
**微软回应**  
  
  
漏洞披露后，微软将这些过度授权的内置角色定性为“低严重性”问题，仅选择更新相关文档，而未限制其权限设置，致使组织仍面临角色被滥用的风险。  
  
相比之下，VPN PSK泄露问题被认定为“严重”漏洞并迅速修复。现在访问密钥必须具备特定权限（Microsoft.Network/connections/sharedKey/action），同时微软还向漏洞发现者支付了7500美元的漏洞赏金。  
  
为防范类似威胁，组织应主动审计并限制上述已识别的过度授权角色的使用，改为基于最小必要权限原则创建自定义角色。  
  
同时，应将角色权限范围限制在具体资源或资源组内，而非整个订阅，从而进一步降低潜在风险。  
  
云安全是服务提供商与客户共同承担的责任。此次事件再次提醒我们：对平台工具的盲目信任可能酿成严重安全后果。  
  
要实现稳健的安全防护，必须持续监控和验证权限配置，防止基于身份的攻击在Azure环境中发生。  
  
# 联想Windows目录可写文件漏洞可隐秘绕过AppLocker防护  
  
研究人员在联想预装Windows操作系统中发现一个安全漏洞——Windows目录下的可写文件 MFGSTAT 可使攻击者绕过微软AppLocker安全框架。该漏洞影响所有采用默认Windows安装的联想设备，对企业安全环境构成威胁。  
  
  
漏洞核心在于C:\Windows\目录下的MFGSTAT.zip文件存在错误权限配置，允许任何经过身份验证的用户对该位置进行写入和执行操作。  
  
  
关键发现：  
  
1. 联想Windows目录下可写的MFGSTAT.zip文件因权限配置错误可绕过AppLocker防护   
  
2. 利用NTFS备用数据流(ADS)在压缩文件中隐藏可执行文件，通过合法Windows进程运行   
  
3. 影响所有预装Windows的联想设备   
  
4. 可通过PowerShell命令或企业管理工具删除该文件  
  
  
**Part01**  
## 漏洞利用技术  
## NTFS备用数据流(ADS)  
  
  
攻击技术利用了NTFS备用数据流(ADS)这一鲜为人知的特性，攻击者可在看似无害的文件中隐藏可执行内容。TrustedSec公司的Oddvar Moe通过以下命令序列，将Microsoft Sysinternals的autoruns.exe工具嵌入存在漏洞的zip文件进行演示：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMV7ndQe367ictR2HO3tL66PPmHEWVbJ0XLTEJ6IbTPMqsHfXFuAlfApAg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
数据流注入后，攻击者可通过合法的Microsoft Office应用程序加载器执行恶意载荷：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMV5xOe7prhQhXE6kqjL4MTiaKBMB04jEIHYHjcwq8ZSR3THzUH8aKbkNQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这种"利用合法二进制文件"(LOLBin)技术通过受信任的Windows进程执行未授权代码，可规避传统安全监控系统。由于完全使用合法系统组件，该攻击向量使安全团队的检测工作变得异常困难。  
  
  
**Part02**  
## 漏洞历史与厂商响应  
  
  
该漏洞最初于2019年常规安全评估中发现，但直到2025年Moe重新调查时才引起关注。在确认该问题影响多代联想设备后，研究人员联系了联想产品安全事件响应团队(PSIRT)。联想回应第一时间提供修复指南，客户可按照修复指南操作来保障安全。  
###   
  
**Part03**  
## 缓解措施  
  
  
企业可通过多种方法立即实施修复。最直接的方式是使用PowerShell删除漏洞文件：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMVsDavVTyBeaO2bV7ricQVITqLOK6ep1cbiaU60YqOG8HesgANEFCkzjLw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
管理员也可使用带隐藏文件属性标志的命令提示符：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMVreGatGJiaSVcnnCYXG0w9E25VcCibyyJnEibkbh3wzdy2kftibBX0uicu9A/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
  
企业环境应利用组策略首选项、System Center Configuration Manager(SCCM)等管理工具确保所有受影响系统完成统一清理。该事件凸显了实施AppLocker部署时全面文件系统审计的重要性，即使微小疏忽也可能造成可绕过基础访问控制的安全漏洞。  
  
  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源： 安全内参、FreeBuf   
  
参考资料：gbhackers.com  
  
参考来源：  
  
Writable File in Lenovo’s Windows Directory Enables a Stealthy AppLocker Bypasshttps://cybersecuritynews.com/writable-file-in-lenovos-windows-directory/  
  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
