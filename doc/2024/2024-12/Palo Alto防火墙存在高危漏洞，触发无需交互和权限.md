#  Palo Alto防火墙存在高危漏洞，触发无需交互和权限   
老布  FreeBuf   2024-12-28 02:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
Palo Alto Networks近日披露，其下一代防火墙中的PAN-OS软件存在一个高危漏洞，编号为CVE-2024-3393。该漏洞允许未经身份验证的攻击者通过发送精心构造的DNS数据包，利用DNS安全特性触发拒绝服务（DoS）状态。若此漏洞被反复利用，可能导致受影响的防火墙重启并进入维护模式。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCwiblgp04ic1dO6w0jWmR5eicpSMfF2OP0kiaAJccDxDYlNs6ucQiaedxyFcA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
问题的根源在于PAN-OS的DNS安全特性对异常情况的处理不当。攻击者可通过防火墙的数据平面发送恶意数据包，进而使其崩溃并重启。此漏洞的CVSS评分为8.7（高），意味着其具有较大的破坏潜力。该攻击复杂性低，无需用户交互和权限，且可通过网络远程执行。  
  
  
该漏洞影响多个版本的PAN-OS：  
> PAN-OS 11.2：受影响版本低于11.2.3；  
> PAN-OS 11.1：受影响版本低于11.1.5；  
> PAN-OS 10.2：受影响版本低于10.2.8，且在维护版本中提供了额外修复；  
> PAN-OS 10.1：受影响版本低于10.1.14。  
  
  
  
使用受影响PAN-OS版本的Prisma Access客户也存在风险。Palo Alto Networks确认，在生产环境中已出现该漏洞被利用的情况，攻击者成功触发了由此导致的DoS攻击。  
  
  
尽管该漏洞不影响机密性或完整性，但对可用性影响很大，所以对依赖这些防火墙进行网络安全保护的组织而言，这是一个关键问题。  
  
  
Palo Alto Networks已发布以下版本的补丁来解决此问题：  
> PAN-OS 10.1.14 - h8  
> PAN-OS 10.2.10 - h12  
> PAN-OS 11.1.5  
> PAN-OS 11.2.3  
  
  
  
强烈建议客户升级到这些版本或更高版本以降低风险。  
  
  
对于无法立即应用修复的用户，临时解决方案包括禁用DNS安全日志记录，具体步骤如下：  
  
1. 导航至对象→安全配置文件→反间谍软件→DNS策略；2. 将所有DNS安全类别的“日志严重性”设置为“无”；3. 提交更改，并在应用修复后恢复设置。  
  
  
使用Palo Alto防火墙的组织应当：  
  
- 立即应用补丁以保护系统；  
  
- 若无法打补丁，则实施推荐的临时解决方案；  
  
- 监控防火墙行为，查看是否有意外重启或进入维护模式的情况；  
  
- 定期查看安全通告并保持软件版本更新。  
  
这一漏洞凸显了及时进行修补管理以及实施强大监控实践的重要性，只有这样才能保护网络基础设施免受新出现威胁的攻击。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
