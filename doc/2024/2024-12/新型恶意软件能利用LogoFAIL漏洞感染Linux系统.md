#  新型恶意软件能利用LogoFAIL漏洞感染Linux系统   
Zicheng  FreeBuf   2024-12-03 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
据BleepingComputer消息，韩国Best of the Best （BoB） 培训计划的网络安全学生利用 LogoFAIL 漏洞创建了新型恶意软件Bootkitty，能够攻击Linux系统设备。  
  
  
固件安全公司Binarly 于2023 年 11 月发现了 LogoFAIL，并警告其可能被用于实际攻击。而安全公司ESET表示，Bootkitty 是第一个专门针对 Linux系统的恶意软件。  
  
  
LogoFAIL 是图像解析代码中的一组缺陷，源自各种硬件供应商使用的 UEFI 固件映像，可被植入 EFI 系统分区 （ESP） 上的恶意图像或徽标利用。Binarly指出，当这些镜像在启动过程中被解析时，可以触发漏洞，并且可以任意执行攻击者控制的有效负载来劫持执行流程并绕过安全启动，包括基于硬件的验证启动机制。  
  
  
根据 Binarly 的最新研究，Bootkitty 在 BMP 文件（"logofail.bmp "和 "logofail_fake.bmp"）中嵌入了 shellcode，通过向 MokList 变体注入流氓认证来绕过安全启动保护。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Ve7IOFZ6CP5p5MV7hJPibpYBxiaTcbarw0FdtGqic02ujE6xRJmlX5d38cIiadicDmVOUz9EjBRqK7zQ/640?wx_fmt=jpeg&from=appmsg "")  
  
恶意图片文件  
  
  
合法的 MokList 被替换为恶意证书，从而有效地授权了恶意引导程序（'bootkit.efi'）。在将执行转移到 shellcode 之后，Bootkitty 会用原始指令恢复漏洞函数 (RLE8ToBlt) 中被覆盖的内存位置，因此任何明显的篡改痕迹都会被清除。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Ve7IOFZ6CP5p5MV7hJPibp3wictozm7MPtJdFGPjoKOSMXvAcl0pvE6A3Ld4KfQOFc1SgAhiaV0ia4w/640?wx_fmt=jpeg&from=appmsg "")  
  
攻击链概述  
##   
  
**对特定硬件的影响**  
  
  
## Bootkitty 可能会影响任何未对 LogoFAIL 进行修补的设备，但其当前的shellcode限于宏碁、惠普、富士通和联想电脑上固件模块使用的特定代码。  
  
研究人员对 bootkit.efi 文件的分析确定，基于 Insyde 的联想设备最容易受到影响，因为 Bootkitty 引用了该品牌使用的特定变量名称和路径。但是，这可能表明开发人员只是在自己的笔记本电脑上测试 bootkit，稍后将添加对更广泛设备的支持。  
  
  
一些最新固件仍然容易受到 LogoFAIL 漏洞的影响，包括联想IdeaPad Pro 5-16IRH8、IdeaPad 1-15IRU7、Legion 7-16IAX7、Legion Pro 5-16IRX8 和Yoga 9-14IRP8。  
  
  
虽然该恶意软件是出于安全目的而研发，但Binarly警告称，自从首次敲响 LogoFAIL 警报以来已经一年多，仍有许多厂商产品仍然会受到 LogoFAIL 漏洞的一种或多种变体的影响。对此，建议受影响的用户限制物理访问、启用安全启动、密码保护 UEFI/BIOS 设置、禁用从外部介质启动，并且只从官方网站下载固件更新。  
  
  
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
  
> https://www.bleepingcomputer.com/news/security/bootkitty-uefi-malware-exploits-logofail-to-infect-linux-systems/  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21&token=734903441&lang=zh_CN#wechat_redirect)  
  
