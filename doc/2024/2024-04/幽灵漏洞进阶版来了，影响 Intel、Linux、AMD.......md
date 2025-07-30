#  幽灵漏洞进阶版来了，影响 Intel、Linux、AMD......   
小薯条  FreeBuf   2024-04-11 19:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
近日，网络安全研究人员披露了针对英特尔系统上 Linux 内核的首个原生 Spectre v2 漏洞，该漏洞是2018 年曝出的严重处理器「幽灵」（Spectre）漏洞 v2 衍生版本，利用该漏洞可以从内存中读取敏感数据，主要影响英特尔处理器 + Linux 发行版组合设备。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38VB88u6BbewDHP8aUyQGYiaiaYOySmCV2hQXXUuGhxd1yeuLryWIUUP6oVXEeeTib6wZyTVEQRU7pWQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
阿姆斯特丹自由大学系统与网络安全小组（VUSec）的研究人员在一份新的研究报告中提到，该漏洞被称为 「本地分支历史注入漏洞」，被追踪为 CVE-2024-2201。此漏洞可以绕过现有的 Spectre v2/BHI 缓解措施，以 3.5 kB/sec 的速度泄漏任意内核内存。  
  
  
现阶段很难有效修复 Spectre v2 漏洞，这和处理器现有的推测执行（Speculative execution）机制有关。  
  
  
推测执行是一种性能优化技术，现代处理器会猜测下一步将执行哪些指令，并提前执行从而加快响应速度。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38VB88u6BbewDHP8aUyQGYiaNHsbJvbLubXr2wWicalCbVOiaqoa2KNQGIWWkiasJM7vhJAhbOYKfSIGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
VUSec 于 2022 年 3 月首次披露了 BHI，并将其描述为一种可以绕过英特尔、AMD 和 Arm 现代处理器中 Spectre v2 保护的技术。虽然该攻击利用了扩展的伯克利数据包过滤器（eBPF），但英特尔为解决该问题提出了禁用 Linux 非特权 eBPF的建议。  
  
  
英特尔公司表示，特权管理运行时可以配置为允许非特权用户在特权域中生成和执行代码--例如Linux的「非特权eBPF」，这大大增加了瞬时执行攻击的风险，即使存在针对模式内分支目标注入的防御措施。  
  
  
可以对内核进行配置，在默认情况下拒绝访问非特权 eBPF，同时仍允许管理员在需要时在运行时启用它。原生 BHI 通过证明 BHI 无需 eBPF 即可实现，从而抵消了这一反制措施。它可能会影响所有易受 BHI 影响的英特尔系统。  
  
  
访问 CPU 资源的攻击者可以通过安装在机器上的恶意软件影响推测执行路径，从而提取与不同进程相关的敏感数据。  
  
  
CERT 协调中心（CERT/CC）在一份公告中提到：禁用特权 eBPF 和启用（Fine）IBT 的现有缓解技术目前不足以阻止针对内核/管理程序的 BHI 攻击。未经认证的攻击者可以利用这个漏洞，通过投机性跳转到所选的小工具，从 CPU 泄漏特权内存。  
  
  
**Spectre v2 漏洞利用**  
  
  
  
经证实，该漏洞已经影响到了 Illumos、英特尔、红帽、SUSE Linux、Triton Data Center 和 Xen等多个系统。  
  
  
据悉，该漏洞是 Spectre v1 的一个变种，能够通过利用推测执行和竞争条件的组合泄漏 CPU 架构的数据。  
  
  
苏黎世联邦理工学院（ETH Zurich）的最新研究披露了一系列被称为 「Ahoi攻击」的攻击，这些攻击可用于破坏基于硬件的可信执行环境（TEE）和破解机密虚拟机（CVM），如AMD安全加密虚拟化-安全嵌套分页（SEV-SNP）和英特尔信任域扩展（TDX）。  
  
  
这些代号为 Heckler 和 WeSee 的攻击利用恶意中断破坏CVM的完整性，允许威胁者远程登录并获得高级访问权限，以及执行任意读、写和代码注入以禁用防火墙规则和打开root shell。  
  
  
研究人员表示：Ahoi 攻击是攻击者通过利用管理程序向受害者的vCPU注入恶意中断，并诱使其执行中断处理程序而实现的。这些中断处理程序可以产生全局效应，比如改变应用程序中的寄存器状态等等，攻击者可以触发这些中断处理程序，从而成功入侵受害者的CVM。  
  
  
目前，英特尔更新了针对 Spectre v2 的缓解建议，现在建议禁用非特权扩展伯克利数据包过滤器（eBPF）功能、启用增强型间接分支限制猜测（eIBRS）和启用监控模式执行保护（SMEP）。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://thehackernews.com/2024/04/researchers-uncover-first-native.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493279&idx=1&sn=d083763c48a2eabb4b9ef4f1e9e71b1a&chksm=ce1f1c00f9689516be84268ea61e623a44cdd020131078b455b68ef05b8582370e25690f2bf1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493151&idx=1&sn=04cf5aa9e777b7acb188efe319cd8233&chksm=ce1f1c80f9689596d54a7990241a1b2af41be38e190cf650d63d18bfa6c7778577ad2c0adab7&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492995&idx=1&sn=cd4660fdf363a0173e2e8fa7f3879710&chksm=ce1f1f1cf968960ac99038a74f5ac2b9718e581753b97ff86f473ae80f1c2cc0e17fa3ed60de&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
