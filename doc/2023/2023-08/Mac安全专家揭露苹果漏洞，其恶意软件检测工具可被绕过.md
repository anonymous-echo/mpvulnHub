#  Mac安全专家揭露苹果漏洞，其恶意软件检测工具可被绕过   
看雪学苑  看雪学苑   2023-08-17 17:59  
  
在美国拉斯维加斯举办的Defcon黑客大会上，长期研究Mac安全的专家Patrick Wardle展示了他对苹果macOS后台任务管理机制的漏洞研究成果——其发现的漏洞可以被利用来绕过苹果最近添加的恶意软件监控工具。  
  
  
我们知道，如果某款软件突兀地持久化，则意味着可能存在恶意行为。基于这一点，苹果在2022年10月发布的macOS Ventura中添加了后台任务管理器，用于在“持久化事件”发生时直接向用户和运行在系统上的第三方安全工具发送通知。  
  
  
Wardle在Defcon上表示：“当某个东西持久化安装在设备上时，应该有那么一款工具来通知用户，这是苹果添加的一个好东西——但具体实施得太糟糕了，以至于任何稍微复杂的恶意软件都可以轻易地绕过监控。”  
  
  
据Wardle所说，他在发现漏洞的契机是，他自己就写过类似的工具，所以对此十分敏感：“我想知道苹果的工具和框架是否也有同样的问题，结果发现确实有。恶意软件仍然可以以完全不可见的方式持久化。”  
  
  
Wardle在周六展示的三种绕过方法中，其中一种需要拥有目标设备root权限。但其余两种则都不需要root权限就能够禁用苹果后台任务管理器发送给用户和安全监控产品的持久化通知。其一利用了警报系统与计算机操作系统核心之间通信的错误；其二利用了一种允许用户（即使没有深层系统权限）将进程置于休眠状态的功能，在通知到达用户之前进行干扰。  
  
  
Wardle此前已向苹果公司报告了这些问题，苹果对此进行了修复。但Wardle表示苹果没有发现该工具的更深层次问题：“就像在飞机坠毁时贴上一些胶带一样，他们没有意识到这个功能需要大量的工作。  
  
  
  
编辑：左右里  
  
资讯来源：Wired  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
洪水攻击  
  
是黑客比较常用的一种攻击技术，特点是实施简单，威力巨大，大多是无视防御的。  
  
从定义上说，攻击者对网络资源发送过量数据时就发生了洪水攻击，这个网络资源可以  
是 router，switch，host，application 等。  
  
洪水攻击将攻击流量比作成洪水，只要攻击流量足够大，就可以将防御手段打穿。  
  
DDoS 攻击便是洪水攻击的一种  
。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
