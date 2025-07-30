#  关键的Windows UI自动化框架漏洞允许黑客绕过EDR   
老布  FreeBuf   2024-12-15 02:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
一种新近开发的技术，利用了Windows的一个辅助功能框架——UI Automation（UIA），来执行多种恶意活动，同时巧妙地避开了端点检测和响应（EDR）解决方案的监控。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibMz3fQrPsXun70eiaxdJGjWc90Yiac4sVw6nLjpOTTIf6tcpnuibwPXCs8UBmeRcAPsKrMNiafe1z9zw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Akamai的安全研究员Tomer Peled在一份与The Hacker News分享的报告中指出：“要利用这项技术，必须说服用户运行一个利用UI Automation的程序。”这可能导致隐蔽的命令执行，进而窃取敏感数据、将浏览器重定向至网络钓鱼网站等。  
  
  
更糟糕的是，本地攻击者可能会利用这一安全漏洞执行命令，从Slack和WhatsApp等消息应用中读取或发送消息。此外，这种技术还可能被用来通过网络操控用户界面元素。  
  
  
UI Automation最初随Windows XP和Microsoft .NET Framework一同推出，旨在提供对各种用户界面（UI）元素的程序化访问，并帮助用户通过辅助技术产品（如屏幕阅读器）来操作这些元素，它也可用于自动化测试场景。  
  
微软在一份支持文件中提到：“辅助技术应用通常需要访问受保护的系统UI元素，或者可能以更高权限运行的其他进程。因此，辅助技术应用必须获得系统的信任，并以特殊权限运行。”  
  
  
“要访问更高权限级别的进程，辅助技术应用必须在应用的清单文件中设置UIAccess标志，并由具有管理员权限的用户启动。”  
  
  
与其他应用中的元素进行UI交互，是通过组件对象模型（COM）作为进程间通信（IPC）机制来实现的。这使得创建UIA对象成为可能，通过设置事件处理程序，在检测到特定UI变化时触发，从而与焦点应用进行交互。  
  
  
Akamai的研究发现，这种方法也可能被滥用，允许恶意行为者读取或发送消息、窃取在网站（如支付信息）中输入的数据，并在浏览器中当前显示的网页刷新或更改时执行命令，将受害者重定向至恶意网站。  
  
  
Peled指出：“除了我们可以在屏幕上与之交互的UI元素外，还有更多的元素被预先加载并存储在缓存中。我们也可以与这些元素交互，比如阅读屏幕上未显示的消息，甚至在屏幕上不显示的情况下设置文本框并发送消息。”  
  
  
需要指出的是，这些恶意场景都是UI Automation的预期功能，类似于Android的辅助服务API已经成为恶意软件从受感染设备中提取信息的常用手段。  
  
  
Peled补充说：“这归根结底是应用程序的预期用途：这些权限级别必须存在才能使用它。这就是为什么UIA能够绕过Defender——应用程序没有发现任何异常。如果某功能被视为特性而非缺陷，机器的逻辑就会遵循这一特性。”  
  
  
Deep Instinct披露，分布式COM（DCOM）远程协议允许软件组件通过网络通信，可能被利用来远程编写自定义有效载荷，创建嵌入式后门。  
  
  
安全研究员Eliran Nissan表示：“这种攻击允许在目标机器上编写自定义DLL，将它们加载到服务中，并使用任意参数执行它们的功能。”这种后门式攻击滥用了IMsiServer COM接口。  
  
  
Nissan说：“到目前为止，DCOM横向移动攻击的研究主要集中在基于IDispatch的COM对象上，因为它们可以被脚本化。”新的“DCOM上传和执行”方法“远程将自定义有效载荷写入受害者的[全局程序集缓存]，从服务上下文执行它们，并与它们通信，有效地充当嵌入式后门。这里的研究证明，许多意想不到的DCOM对象可能被用于横向移动，应该对齐适当的防御措施。”  
  
  
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
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://thehackernews.com/2024/12/new-malware-technique-could-exploit.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
