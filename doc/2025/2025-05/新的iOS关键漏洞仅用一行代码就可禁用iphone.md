#  新的iOS关键漏洞仅用一行代码就可禁用iphone   
 嘶吼专业版   2025-04-30 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
根据安全研究人员最新发现，iOS系统的一个关键漏洞可能允许恶意应用程序仅用一行代码就永久禁用iphone。该漏洞被命名为CVE-2025-24091，利用操作系统的达尔文通知系统触发无尽的重启周期，有效地“阻塞”设备并需要完整的系统恢复。  
# iOS Darwin通知漏洞  
  
该漏洞利用了Darwin通知，这是CoreOS层中的一种低级消息传递机制，允许进程通信系统范围的事件。  
  
与NSNotificationCenter或NSDistributedNotificationCenter等更常见的通知系统不同，Darwin通知是传统API的一部分，在苹果操作系统的基础层面上运行。  
  
安全研究员Guilherme Rambo发现了这一漏洞，他解释说：“  
Darwin通知甚至更简单，因为它们是CoreOS层的一部分。它们为苹果操作系统上的进程之间提供了一种简单的消息交换底层机制。”  
  
关键漏洞在于，iOS上的任何应用程序都可以在无需特殊权限或授权的情况下发送敏感的系统级Darwin通知。  
  
最危险的一点在于，这些通知可能会触发强大的系统功能，包括进入“正在恢复”模式。  
# 仅需一行代码即可完成  
  
该漏洞利用起来非常简单——只需一行代码就能触发漏洞：当执行此代码时，会迫使设备进入“正在恢复”状态。由于实际上并未进行恢复操作，该过程必然失败，从而提示用户重启设备。  
  
研究人员创建了一个名为“VeryEvilNotify”的概念验证攻击，将此漏洞利用程序嵌入到了一个小部件扩展中。并指出：“iOS 会定期在后台唤醒部件扩展。”  
  
由于系统中小部件的使用非常普遍，所以当安装并启动包含小部件扩展的新应用时，系统会非常急切地执行其小部件扩展。  
  
通过将漏洞利用程序置于一个在发送通知后会反复崩溃的小部件中，研究人员制造了一种持续攻击，每次重启后都会触发，形成一个无休止的循环，致使设备无法使用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWQWszjjKRIoP3QVibeZ7v1H8j1f0M2BDqNMxJAGNfBVandArzRxUvK8A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWpK6zgFcwJyz2S6LKUVSApW4Ly6qe86dRRrOoXiaSC0VoZlTqGgfZkAg/640?wx_fmt=png&from=appmsg "")  
  
缓解措施  
苹果公司在iOS 18.3中通过为敏感的Darwin 通知实施新的授权系统解决了这一漏洞。该研究人员获得了17500美元的漏洞赏金。  
  
具体来说，系统通知现在需要以“com.apple.private.restrict-post.”为前缀，并且发送进程必须具备以“com.apple.private.darwin-notification.restrict-post.  
  
这并非苹果系统中首次出现与  
Darwin相关的漏洞。此前，卡巴斯基实验室曾发现一个名为“  
Darwin核弹”的漏洞，该漏洞能让远程攻击者通过专门设计的网络数据包发起拒绝服务攻击。  
  
强烈建议所有iPhone用户立即更新至iOS 18.3或更高版本。运行早期版本的设备仍易受此攻击，该攻击可能通过看似无害的应用程序或小部件通过App Store或其他分发方式部署。  
  
该案例凸显了移动操作系统中持续存在的安全挑战，即便是简单且容易被忽视的旧版应用程序编程接口（API），如果安全防护不当，也会带来重大风险。  
  
参考及来源：  
https://cybersecuritynews.com/ios-critical-vulnerability-brick-iphones/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWib9YgrRRIsibic6ETEwE9W4vp13jdAib1EJa0j1US7UzYMuiazMtJlkGicdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWeqvicwiapa0SBClpS879LOn0tD2UfyyMclicV34GCpnPjA1qYYm71MgXw/640?wx_fmt=png&from=appmsg "")  
  
  
