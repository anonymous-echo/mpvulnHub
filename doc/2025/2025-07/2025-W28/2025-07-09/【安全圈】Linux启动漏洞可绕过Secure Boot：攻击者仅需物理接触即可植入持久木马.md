> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070569&idx=2&sn=190752ffac23d6be9ddec582d3384a58

#  【安全圈】Linux启动漏洞可绕过Secure Boot：攻击者仅需物理接触即可植入持久木马  
 安全圈   2025-07-09 11:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
网络攻击  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgIZ8pTYPudA7ZzJtiakMsU43knribFr7yBcGd0SZ4edBgNg4JwmKJHDgH4CDw8gia1M4PLvyoFHzZTA/640?wx_fmt=png&from=appmsg "")  
  
研究人员披露，现代Linux发行版存在**严重启动安全漏洞**  
，攻击者只需**短暂物理接触**  
，即可通过篡改
```
initramfs
```

  
（初始内存文件系统）绕过Secure Boot机制，**在系统重启后仍可保持持久控制**  
。  
  
该漏洞利用了Linux系统启动失败期间**可访问的调试Shell接口**  
，使得攻击者能够**注入长期驻留的恶意程序**  
，即便用户随后输入了正确的加密分区密码，攻击仍能持续生效。  
### 核心要点概览：  
1. 攻击者通过利用
```
initramfs
```

  
中调试Shell，在多次输入错误密码后**绕过Secure Boot保护**  
；  
  
1. 可将恶意木马植入未签名的
```
initramfs
```

  
组件中，实现系统重启后的**跨会话驻留**  
；  
  
1. **Ubuntu 25.04、Debian 12、Fedora 42、AlmaLinux 10**  
均受影响，**OpenSUSE Tumbleweed**  
默认安全；  
  
1. 添加内核参数（如Ubuntu加 
```
panic=0
```

  
，RedHat系加 
```
rd.shell=0 rd.emergency=halt
```

  
）可禁用调试Shell并缓解风险。  
  
### 漏洞细节：Linux initramfs未签名组件被滥用  
  
安全研究员 **Alexander Moch**  
 表示，该漏洞的核心在于Linux引导流程中的**
```
initramfs
```

  
未签名性**。作为解密根分区的关键引导组件，
```
initramfs
```

  
默认并未采用签名保护，这成为整个Secure Boot链条中的**“薄弱环节”**。  
  
在多次输入加密根分区密码错误后，多个主流发行版会**自动进入调试Shell模式**  
，为攻击者提供可操作窗口。  
###   
### 攻击过程：植入木马脚本并保持长期控制  
  
攻击者可插入U盘，借助调试Shell加载恶意工具链，过程如下：  
1. 使用 
```
unmkinitramfs
```

  
 解包当前系统的
```
initramfs
```

  
；  
  
1. 在 
```
scripts/local-bottom/
```

  
 目录中植入**恶意hook脚本**  
；  
  
1. 利用 
```
cpio
```

  
 和 
```
gzip
```

  
 等工具重新打包
```
initramfs
```

  
；  
  
1. 覆盖原系统的
```
initramfs
```

  
，攻击完成。  
  
Moch展示的PoC中，恶意hook在系统解密根分区后执行，可将文件系统挂载为可写，并建立持久后门。  
  
由于**攻击未涉及签名内核镜像修改**  
，且完全遵循正常引导流程，因此可规避常规安全防护机制，隐蔽性极强。  
### 不同发行版受影响程度不同  
  
研究测试显示，不同Linux发行版对该攻击的防御能力不一：  
- **Ubuntu 25.04**  
：仅需三次密码错误，即可触发调试Shell；  
  
- **Debian 12**  
：长按回车约一分钟也可进入Shell模式；  
  
- **Fedora 42 / AlmaLinux 10**  
：虽然默认initramfs中无
```
usb_storage
```

  
模块，但攻击者可通过 
```
Ctrl+Alt+Delete
```

  
 重启后进入救援模式规避；  
  
- **OpenSUSE Tumbleweed**  
：采用默认引导分区加密机制，**可阻止攻击路径**  
。  
  
该攻击符合所谓“**邪恶女仆攻击（Evil Maid）**  
”场景——即攻击者仅需一次短暂的物理接触，即可实现系统持久性控制。  
###   
### 防护建议：添加内核参数，构建完整启动安全链  
  
针对该攻击路径，研究人员提出以下防御措施：  
1. **禁用调试Shell访问**  
：  
  
1. Ubuntu系：内核参数中添加 
```
panic=0
```

  
；  
  
1. RedHat系：添加 
```
rd.shell=0 rd.emergency=halt
```

  
。  
  
1. **强化启动过程控制**  
：  
  
1. 启用**Bootloader密码保护**  
；  
  
1. 对启动分区启用 **LUKS加密**  
；  
  
1. 开启SSD原生硬件加密。  
  
1. **部署高级安全机制**  
：  
  
1. 使用 **UKI（统一内核映像）**  
：将内核与initramfs封装为**单一签名二进制文件**  
；  
  
1. 启用 **TPM（受信平台模块）**  
：将initramfs完整性写入PCR（平台配置寄存器），防止篡改。  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】中国男子在意大利被捕 美方指控其涉疫苗间谍活动](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=1&sn=6202ead586d7e2b376c3fcd1d53d31e0&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Hunters International 勒索组织宣布关闭，重塑品牌为 “World Leaks” 专注数据勒索](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=2&sn=de13272b722142292b64c67f3b92c93f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】勒索软件团伙 SatanLock 宣布关闭，声称将泄露所有被盗数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=3&sn=5266c0ef59045ec30e5bb45ac8a72972&scene=21#wechat_redirect)  
  
  
  
[【安全圈】《使命召唤：二战》曝严重漏洞，PC玩家遭远程黑客攻击，游戏被紧急下线](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=4&sn=a0045b414dc83b5ccab5d88ec4c10558&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
