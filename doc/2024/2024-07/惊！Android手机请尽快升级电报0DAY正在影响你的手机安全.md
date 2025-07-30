#  惊！Android手机请尽快升级:电报0DAY正在影响你的手机安全   
原创 小编  像梦又似花   2024-07-24 20:00  
  
**ESET的研究人员发现了一个Android的零日电报漏洞，允许发送伪装成视频的恶意文件**  
  
ESET研究人员发现了一个针对Android版Telegram的零日漏洞，该漏洞于2024年6月6日在地下论坛帖子中以未指明的价格出售销售。利用该漏洞来滥用ESET研究团队命名为EvilVideo的漏洞，攻击者可以通过Telegram频道，群组和聊天共享恶意Android有效载荷，并使它们显示为多媒体文件。  
  
ESET研究团队能够找到一个漏洞利用的例子，使ESET研究团队能够进一步分析它，并在2024年6月26日将其报告给Telegram。7月11日，他们发布了一个更新，修复了Telegram 10. 14. 5及以上版本中的漏洞。  
  
时间节点：  
  
2024年6月26日：在2024年的一个地下论坛上，ESET研究团队发现了一个针对Android版Telegram的零日漏洞利用的广告。  
  
ESET研究团队将这个漏洞命名为EvilVideo，并将其报告给Telegram;他们的团队在7月11日修补了它。  
  
EvilVideo允许攻击者发送恶意有效负载，这些负载在未修补的Telegram for Android中显示为视频文件  
  
适应版本：  
  
该漏洞仅适用于Android Telegram版本10.14.4及更早版本。  
  
>>> Android Telegram < 10.14.4及更早版本  
## 发现  
  
ESET研究团队在一个地下论坛上发现了这个漏洞的销售广告。图1  
  
在帖子中，卖家展示了在公共Telegram频道测试漏洞的截图和视频。ESET研究团队能够识别出有问题的通道，漏洞仍然可用。这使ESET研究团队能够得到ESET研究团队的手在有效载荷和测试它自己。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvg6lcJNBfUiahv5kbR6fsCPPy7P5N87HA8qvVWS7gY3KiawoWtBjQibuECA/640?wx_fmt=png&from=appmsg "")  
  
[ 图1 ]  
## 分析  
  
ESET研究团队对该漏洞的分析显示，它适用于Telegram 10.14.4及更早版本。ESET研究团队推测，特定的有效载荷最有可能是使用Telegram API制作的，因为它允许开发人员以编程方式将专门制作的多媒体文件上传到Telegram聊天或频道。  
  
该漏洞似乎依赖于威胁行为者能够创建一个有效载荷，将Android应用程序显示为多媒体预览，而不是二进制附件。一旦在聊天中共享，恶意负载将显示为30秒的视频（图2）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvg9x7o6NI3lCbTdd7PXcIwCl92NCicONmdnZsSStMSTTyGiaX4WQDZOWqQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
[ 图2 ]  
  
默认情况下，通过Telegram接收的媒体文件设置为自动下载。这意味着启用该选项的用户一旦打开共享会话，就会自动下载恶意负载。可以手动禁用该选项-在这种情况下，仍然可以通过点击共享的外观视频左上角的下载按钮来下载有效负载  
  
如果用户试图播放“视频”，Telegram会显示一条消息，指出无法播放，并建议使用外部播放器（参见图4）。这是ESET研究团队在合法Telegram for Android应用程序的源代码中发现的原始Telegram警告;它不是由恶意有效负载精心制作和推送的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvghRUNHS5rGMHBiaepvScQ3cHibO40XAImFvyoqcET1NI0ThnxI8CjI6QA/640?wx_fmt=png&from=appmsg "")  
  
[ 图3 ]电报警告说，它不能播放“视频  
  
但是，如果用户点击显示消息中的“打开”按钮，他们将被要求安装伪装成上述外部播放器的恶意应用程序。如图5所示，在安装之前，Telegram会要求用户启用未知应用的安装。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvgwppAAGwZtDSJkzRy25ke1C5woxUWibib1YrrB5f3GEqelfl871kArp0w/640?wx_fmt=png&from=appmsg "")  
  
[ 图4 ]Telegram请求用户允许其安装未知应用程序  
  
此时，有问题的恶意应用程序已经作为明显的视频文件下载，但扩展名为.apk。有趣的是，正是漏洞的性质使共享文件看起来像视频-实际的恶意应用程序没有被修改为多媒体文件，这表明上传过程很可能被利用。恶意应用的安装请求如图5所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvgU7kYPhcLicdcREK2qpiaUNTbDccomWamib4VmvZqZYR3n6OqG5Y5o0CDw/640?wx_fmt=png&from=appmsg "")  
  
[ 图5 ] 请求安装恶意负载，攻击后检测为Android/Spy.SpyMax.T  
  
不幸的是，ESET研究团队无法复制漏洞，只能检查和验证卖方共享的样本。  
  
其他操作系统：  
  
尽管有效载荷仅针对Android版Telegram，但ESET研究团队仍然尝试在其他Telegram客户端上测试其行为。ESET研究团队测试了Windows版的Telegram Web客户端和Telegram Desktop客户端-正如预期的那样，该漏洞在两者上都不起作用。  
  
在Telegram Web的情况下，在ESET研究团队尝试播放“视频”之后，客户端显示一条错误消息，说尝试使用桌面应用程序打开视频（参见图7）。手动下载附件显示其名称和扩展名为Teating.mp4。虽然该文件本身实际上是一个Android可执行二进制文件（APK），但Telegram将其视为MP4文件阻止了该漏洞的工作：为了使其成功，附件必须具有.apk扩展名。  
  
Windows版Telegram Desktop客户端也发生了非常类似的事情：下载的文件名为Teating.apk.mp4，因此它再次成为一个扩展名为.mp4的APK二进制文件。这表明，即使攻击者精心制作了一个Windows可执行文件来代替Android APK，它仍然会被视为一个多媒体文件，利用该漏洞也不会起作用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvgV7ibErvYhWvqySoHrE910Pfy6GPASKBpbUCtfCsUQawUqRf4iaSVtKIQ/640?wx_fmt=png&from=appmsg "")  
  
[ 图6 ] 触发利用时来自Telegram Web的错误消息  
## 威胁行为  
  
虽然ESET研究团队对威胁行为者知之甚少，但ESET研究团队设法找到了他们提供的另一项可疑服务，该服务基于卖家在其论坛帖子中分享的Telegram句柄。除了利用漏洞，他们还一直在使用同一个地下论坛来宣传他们声称自2024年1月11日以来完全无法检测的Android加密即服务（FUD）。论坛帖子如图7所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvgVGpDOF6FAKQm5UhOW9sNIWAQdJ9yBRXEn1UTUE7dTANibM9lXF9mqtg/640?wx_fmt=png&from=appmsg "")  
  
[ 图7 ]地下论坛帖子广告Android加密即服务  
## 漏洞报告  
  
在2024年6月26日发现EvilVideo漏洞后，ESET研究团队遵循了ESET研究团队  
协调的披露政策  
，并将其报告给了Telegram，但当时没有收到任何回应。ESET研究团队在7月4日再次报告了该漏洞，而那一次，Telegram在同一天联系了ESET研究团队，确认其团队正在调查EvilVideo。他们修复了这个问题，在7月11日发布了10.14.5版本，并通过电子邮件通知了ESET研究团队.  
  
该漏洞影响了所有版本的Telegram for Android，最高可达10.14.4，但已在10.14.5版本中进行了修补。正如ESET研究团队所验证的，聊天多媒体预览现在正确地显示共享文件是一个应用程序（图8），而不是一个视频。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/biachO2ia6rWB4FBctfhdb3I8ujdcN1mvgWgC1uVlkxP3G8FHRLQVbqzicMuStQV7JmR6NRnM5725JItNebID3lmA/640?wx_fmt=jpeg&from=appmsg "")  
  
[ 图8 ]Telegram 10.14.5版聊天正确显示共享二进制文件的性质  
## 结论  
  
ESET研究团队在一个地下论坛上发现了一个用于销售Android的零日电报漏洞。它利用的漏洞允许通过Telegram聊天发送看起来像多媒体文件的恶意有效载荷。如果用户试图播放明显的视频，他们将收到安装外部应用程序的请求，这实际上安装了恶意负载。幸运的是，在ESET研究团队向Telegram报告之后，该漏洞已于2024年7月11日修复。  
### 文件  
<table><tbody><tr style="height: 33px;"><td width="179" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>SHA-1</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>Sha-1</span></p></td><td width="132" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Filename</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>文件名</span></p></td><td width="170" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Detection</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>检测</span></p></td><td width="161" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Description</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>描述</span></p></td></tr><tr style="height: 33px;"><td width="179" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>F159886DCF9021F41EAA<br/>2B0641A758C4F0C4033D</span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>F159886DCF9021F41EAA<br/>2B0641A758C4F0C4033D</span></p></td><td width="132" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>Teating.apk</span></p></td><td width="170" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>Android/Spy.SpyMax.T</span></p></td><td width="161" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>EvilVideo payload.</span><span>EvilVideo有效载荷。</span></p></td></tr></tbody></table>### 网络  
<table><tbody><tr style="height: 33px;"><td width="147" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>IP</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>IP</span></p></td><td width="145" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Domain</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>域</span></p></td><td width="132" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Hosting provider</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>托管服务提供商</span></p></td><td width="95" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>First seen</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>第一次看到</span></p></td><td width="123" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Details</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>细节</span></p></td></tr><tr style="height: 33px;"><td width="147" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>183.83.172[.]232</span><span>183.83.172[.] 232</span></p></td><td width="145" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>infinityhackscharan.<br/>ddns[.]net</span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>无限黑客<br/>ddns[.]净</span></p></td><td width="132" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>Administrator Beam Cable System</span><span>管理员梁电缆系统</span></p></td><td width="95" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>2024‑07‑16</span></p></td><td width="123" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>C&amp;C server of EvilVideo payload.</span><span>邪恶视频的C&amp;C服务器。</span></p></td></tr></tbody></table>## MITRE ATT CK技术  
<table><tbody><tr style="height: 33px;"><td width="113" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Tactic</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>战术</span></p></td><td width="113" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>ID</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>ID</span></p></td><td width="151" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Name</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>名称</span></p></td><td width="265" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Description</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>描述</span></p></td></tr><tr style="height: 33px;"><td width="113" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Initial Access</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>初始接入</span></p></td><td width="113" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>T1664</span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>T1664</span></p></td><td width="151" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>Exploitation for Initial Access</span><span>对初始访问的利用</span></p></td><td width="265" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>The EvilVideo vulnerability can be abused by Android malware to achieve initial device access.</span><span><br/></span><span>EvilVideo漏洞可被Android恶意软件滥用，以实现初始设备访问。</span></p></td></tr><tr style="height: 33px;"><td width="113" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span>Execution</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>执行</span></p></td><td width="113" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>T1658</span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span><br/><br/></span></p><p style="margin: 0;padding: 0;min-height: 24px;"><span>T1658</span></p></td><td width="151" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>Exploitation for Client Execution</span><span>针对客户端执行的攻击</span></p></td><td width="265" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>The EvilVideo vulnerability tricks the victim into installing a malicious app that impersonates a multimedia file.</span><span><br/></span><span>EvilVideo漏洞欺骗受害者安装一个模仿多媒体文件的恶意应用程序。</span></p></td></tr></tbody></table>  
  
本文转载：  
https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/  
  
