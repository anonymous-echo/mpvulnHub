#  SonicWall SSL VPN曝出高危漏洞，可能导致防火墙崩溃   
小薯条  FreeBuf   2024-09-10 19:07  
  
##   
  
  
近日，有黑客利用 SonicWall SonicOS 防火墙设备中的一个关键安全漏洞入侵受害者的网络。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ErnpjItp6uIbj2K9DzpLRDOS7VUsZZBia65jr4VicWDx886wP0fxdkJ7joRjGamrSE6t9pXFFCfJQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这个不当访问控制漏洞被追踪为 CVE-2024-40766，影响到第 5 代、第 6 代和第 7 代防火墙。SonicWall于8月22日对其进行了修补，并警告称其只影响防火墙的管理访问界面。  
  
  
然而，SonicWall上周五（9月6日）透露，该安全漏洞还影响了防火墙的SSLVPN功能，且已被黑客用以网络攻击。该公司提醒客户尽快为受影响的产品打上补丁，但没有透露有关野外利用的详细信息。  
  
  
Arctic Wolf的安全研究人员认为这些攻击与Akira勒索软件背后的运营者有所关联，他们试图以SonicWall设备为目标，获得对目标网络的初始访问权。  
  
  
Arctic Wolf高级威胁情报研究员Stefan Hostetler表示：在每个实例中，被攻击的账户都是设备本身的本地账户，而不是与微软活动目录等集中式身份验证解决方案集成在一起。此外，所有被入侵账户的 MFA 都被禁用，受影响设备上的 SonicOS 固件属于已知易受 CVE-2024-40766 影响的版本。  
  
  
同时，网络安全机构Rapid7也在最近的事件中发现了针对SonicWall SSLVPN账户的勒索软件组织，但其表示将CVE-2024-40766与这些事件联系起来的证据仍然是间接的。  
  
  
Arctic Wolf 和 Rapid7 复制了 SonicWall 的警告，并敦促管理员尽快升级到最新的 SonicOS 固件版本。  
##   
  
**联邦机构被勒令在 9 月 30 日前打补丁**  
  
  
## 本周一（9月9日），CISA将此关键访问控制漏洞添加到其已知漏洞目录中，并命令联邦机构在 9 月 30 日之前的三周内，按照约束性操作指令 (BOD) 22-01 的规定，确保其网络中存在漏洞的 SonicWall 防火墙的安全。  
  
  
SonicWall 缓解建议将防火墙管理和 SSLVPN 访问限制为可信来源，并尽可能禁止互联网访问。管理员还应为所有使用 TOTP 或基于电子邮件的一次性密码 (OTP) 的 SSLVPN 用户启用多因素身份验证 (MFA)。  
  
  
在网络间谍和勒索软件攻击中，攻击者经常以 SonicWall 设备和设备为目标。例如，包括HelloKitty和FiveHands在内的多个勒索软件团伙也利用SonicWall的安全漏洞初步访问了受害者的企业网络。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/critical-sonicwall-sslvpn-bug-exploited-in-ransomware-attacks/  
  
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494804&idx=1&sn=3f8abfd1c27c79f9a511cd9e9f3b8443&chksm=ce1f160bf9689f1d4d0102e41e9ebe4c36239bdf77ba1939742f917e9d839397af22b7d08896&token=1056323174&lang=zh_CN&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494785&idx=1&sn=9fb76edd4009af6f5cfdf4c7fc19ae1b&chksm=ce1f161ef9689f0803457ac72b1337a2b371c4d53779f73d7ca5278ff497255a512e4f1ccf96&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
