#  微软AI工具发现GRUB2和U-boot引导程序高危漏洞   
 FreeBuf   2025-04-03 19:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
微软威胁情报团队利用其AI驱动的Security Copilot工具，在广泛使用的开源引导程序GRUB2、U-Boot和Barebox中发现了20个高危漏洞。这些引导程序对操作系统初始化至关重要，特别是在基于Linux的环境和嵌入式系统中。  
  
  
新发现的漏洞影响采用统一可扩展固件接口(UEFI)安全启动的系统，包括物联网设备、云基础设施和企业IT环境。微软在博客中表示，这些漏洞（包括一个可利用的整数溢出问题）可能允许攻击者执行任意代码。就GRUB2而言，攻击者可能绕过安全启动，安装隐蔽的引导工具包(bootkit)，并规避BitLocker加密等企业安全机制。  
  
  
![Microsoft Windows Copilot Recall](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJ1UiaObonmWJbuLyoLXdutgaicdXw8HdbenHjtbBMwyA5bjeSia7zKhZ1FGqyxzdG80z8aB2C3bJHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**持久性恶意软件威胁**  
  
  
虽然利用U-boot或Barebox漏洞可能需要物理设备访问权限，但GRUB2漏洞对企业环境构成更大威胁。微软指出，最令人担忧的是可能创建持久性恶意软件，即使在操作系统重新安装或硬盘更换后仍能保持完整。  
  
  
Everest Group高级分析师Prabhjyot Kaur表示："这些引导程序漏洞——尤其是GRUB2中的漏洞——非常重要，因为它们使攻击者能够植入即使在操作系统重新安装或存储驱动器更换后仍能持续的恶意软件。政府、金融、医疗保健和关键基础设施等高安全部门应立即优先打补丁。"  
  
  
微软已向所有受影响的引导程序维护者披露了这些漏洞，并合作开发修复程序。博客补充说，安全更新已于2025年2月中旬发布，GRUB2补丁于2月18日提供，U-boot和Barebox补丁于2月19日发布。  
  
  
**AI驱动的发现改变网络安全格局**  
  
  
  
微软的Security Copilot工具显著加快了漏洞识别过程，特别关注文件系统实现，因为它们具有很高的漏洞可能性。博客指出："使用Security Copilot，我们能够识别引导程序功能中的潜在安全问题，重点关注文件系统，因为它们具有很高的漏洞可能性。这种方法为我们的团队节省了大约一周的时间，否则这些时间将用于手动审查内容。"  
  
  
Beagle Security顾问Sunil Varkey表示："我们看到的主要转变是从传统的负责任披露方法转变为完全不同的方式。当AI以这种加速的速度发现漏洞时，我们很可能会在野外看到更多的零日漏洞。"  
  
  
**对企业安全的影响**  
  
  
  
对于企业安全团队来说，这些发现凸显了保持固件和引导程序最新状态的重要性——这些领域在常规补丁管理过程中经常被忽视。安全专家建议组织清点受影响系统，优先应用2025年2月的安全更新，实施对利用尝试的监控，并审查固件更新流程以确保引导程序包含在常规安全维护中。  
  
  
Kaur建议："组织应制定明确解决固件和引导程序更新的政策，维护硬件清单，记录哪些系统使用受影响的引导程序，并将这些较低级别的组件纳入现有的补丁管理周期。"  
  
  
Varkey指出，解决引导程序漏洞面临独特挑战："虽然在固件层面缓解此类漏洞至关重要，但这始终是一个严峻的挑战。在大多数情况下，缓解补丁可能不可用，它们的发布高度依赖OEM供应商的优先级——类似于OT设备和其他固件的挑战。"  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
