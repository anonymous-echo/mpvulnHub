> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247514637&idx=1&sn=fa07c6d1743943a472d11181a4524966

#  微软云身份曝严重漏洞：对低级别用户过度授权，导致客户VPN密钥泄露  
安全内参编译  安全内参   2025-07-04 08:32  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7vI437xjqWcNyOqqwqLp91PIWOUkeSJhzu6HT2QVMuiaugoC6icsQ5RLzAzjicgywHzBGad8lIpR6w1g/640?wx_fmt=jpeg "")  
  
  
Azure通过HTTP方法区分权限控制。只读操作使用GET，而访问敏感数据则需通过POST请求，但由于设计疏忽，VPN连接的共享密钥竟被设置为通过GET请求获取，从而绕过了应有的安全防护机制，使得  
被过度授权的  
最低级别读取权限也能获取VPN PSK。  
  
  
前情回顾·  
全球公有云漏洞频发  
- [谷歌云被曝重大漏洞：或影响数百万台服务器](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247512642&idx=2&sn=028197550edfd20b6316e7d8e8b1f2e9&scene=21#wechat_redirect)  
  
  
- [谷歌容器云曝“严重风险”：上千Kubernetes集群可能暴露，涉某上市公司](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247510914&idx=1&sn=8d013abfc5e69051f64029a5cf0ae80c&scene=21#wechat_redirect)  
  
  
- [阿里云数据库曝出两个严重漏洞，全球公有云漏洞层出不穷](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247508453&idx=1&sn=9e8fae986be9414269b82315cd57090c&scene=21#wechat_redirect)  
  
  
- [亚马逊云曝出“超级漏洞”，攻击者可删除任何镜像](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247507166&idx=1&sn=655b061acc3015c87c89086486324586&scene=21#wechat_redirect)  
  
  
  
  
安全内参7月4日消息，以色列身份安全厂商Token Security安全专家近期开展了一项深入调查，揭示微软Azure云平台RBAC（基于角色的访问控制）架构中存在严重安全漏洞。  
  
Azure RBAC是该云平台权限管理的核心机制，允许管理员根据不同的范围（从整个订阅到具体资源）为用户、用户组或服务主体分配具有预定义权限的角色。  
  
然而调查发现，多个原本设计用于提供受限、特定服务访问权限的内置角色存在配置错误，其实际权限远远超出设定范围。  
  
包括“托管应用读取”和“日志分析读取”在内，有10个角色被错误地授予了过于宽泛的*/read权限，实际上等同于通用的“读取者”（Reader）角色。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7vE38iaEkrUaY3vMGkJI1iabwHjS1EO2RdM34nlc4rhibzYgKbPAhicZyUSicBHqEa0oXkzy7MfXyh6rcg/640?wx_fmt=png&from=appmsg "")  
  
图：角色分配  
  
这一问题导致用户能够访问所有Azure资源的敏感元数据，权限范围远超这些角色描述所设定的界限。  
  
权限的过度授予可能使攻击者得以从自动化账户中提取凭证、绘制网络配置图以辅助后续攻击，并在存储账户或备份保管库中发现关键数据，为权限提升和攻击部署创造有利条件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7vE38iaEkrUaY3vMGkJI1iabwWdcKhvBB7wGY9VONUvC2u5DyF4PotCzSZLyxY21c9FkRULRYSfOxLg/640?wx_fmt=webp&from=appmsg "")  
  
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
  
相比之下，VPN PSK泄露问题被认定为“严重”漏洞并迅速修复。现在访问密钥必须具备特定权限  
（Microsoft.Network/connections/sharedKey/action），同时微软还向漏洞发现者支付了7500美元的漏洞赏金。  
  
为防范类似威胁，组织应主动审计并限制上述已识别的过度授权角色的使用，改为基于最小必要权限原则创建自定义角色。  
  
同时，应将角色权限范围限制在具体资源或资源组内，而非整个订阅，从而进一步降低潜在风险。  
  
云安全是服务提供商与客户共同承担的责任。此次事件再次提醒我们：对平台工具的盲目信任可能酿成严重安全后果。  
  
要实现稳健的安全防护，必须持续监控和验证权限配置，防止基于身份的攻击在Azure环境中发生。  
  
  
**参考资料：gbhackers.com**  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
