#  Telegram零日漏洞被售卖数周：恶意APK文件可伪装成视频消息   
 网络安全与人工智能研究中心   2024-07-25 18:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibweTPiagluQN22ibJMvG8op7qZLTMn6XWdpRC9c222H5SmJgjm6Wjjgc3NhNJS3rg6d7u1Z3dhsnP6Q/640?wx_fmt=gif&from=appmsg "")  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibweTPiagluQN22ibJMvG8op7qR1tnSsRygdf98RgvElUQEibRgcwahwxDP0ibS7ykRoYicMO8Gv9MmICjg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**利用该漏洞需要多步交互和授权，这大大降低了攻击成功的风险；**  
  
****  
**相关零日漏洞在地下论坛长期售卖，也说明了攻击者的旺盛需求，用户需要尽可能保持安全使用习惯。**  
  
安全内参7月23日消息，一个名为“EvilVideo”的Telegram安卓版零日漏洞，允许攻击者将恶意的安卓APK有效负载伪装成视频文件发送。  
  
6月6日，威胁行为者“Ancryno”在XSS俄语黑客论坛上发帖，首次销售Telegram零日漏洞利用工具，称此漏洞存在于Telegram v10.14.4及更早版本中。  
欧洲安全厂商ESET的研究人员在一个公共Telegram频道上，分享概念验证（PoC）演示后发现了该漏洞，藉此获取了恶意有效负载。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibweTPiagluQN22ibJMvG8op7q0QXn3frEN2dHJjsLzGJuP1YYmULApE5QiaKytoHibABCIgNVT91QNgnA/640?wx_fmt=jpeg&from=appmsg "")  
  
图：威胁行为者在黑客论坛上出售漏洞利用工具  
  
  
ESET确认该漏洞在Telegram v10.14.4及更早版本中有效，并将其命名为“EvilVideo”。ESET研究员Lukas Stefanko于6月26日和7月4日两次向Telegram负责任地披露了该漏洞。  
Telegram于7月4日回应称，正在调查上报的漏洞，并在7月11日发布的10.14.5版本中修补了该漏洞。  
这意味着威胁行为者至少有五周的时间，可以利用该零日漏洞进行攻击。  
目前尚不清楚该漏洞是否在攻击中被积极利用，ESET分享了恶意有效负载使用的C2服务器地址“infinityhackscharan.ddns[.]net”。  
外媒BleepingComputer在VirusTotal上发现了两个使用该C2的恶意APK文件，它们伪装成Avast Antivirus或“xHamster Premium Mod”。  
  
  
**Telegram零日漏洞利用情况**  
  
  
  
EvilVideo零日漏洞仅在Telegram安卓版上有效。该漏洞允许攻击者创建特制的APK文件。当这些文件被发送给其他Telegram用户时，会显示为嵌入视频。  
ESET认为，该漏洞利用了Telegram API以编程方式创建信息。信息看似一条30秒长的视频。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibweTPiagluQN22ibJMvG8op7qmF0oq8fhX2wRUPF8RXloibFao3YOFLLDZbuic7XtvHHgvtJqERq93ibsQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
图：APK文件预览为30秒视频片段  
  
在默认设置下，安卓上的Telegram应用会自动下载媒体文件。因此频道参与者一旦打开对话就会在设备上收到有效负载。  
即便已禁用自动下载，用户只要轻触视频预览就会开始下载文件。  
当用户尝试播放假视频时，Telegram会建议使用外部播放器。在这种情况下，接收者可能会点击“打开”按钮并执行有效负载。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibweTPiagluQN22ibJMvG8op7qfXdOBhmzu5KQ3nOicYz2NRXbrucMtia6CsYtuicSfZoAe6ZB1gqQcOiaPQ/640?wx_fmt=jpeg&from=appmsg "")  
  
图：启动外部视频播放器的提示  
  
接下来还需要额外一步：受害者必须在设备设置中启用安装未知应用程序，允许恶意APK文件在设备上安装。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibweTPiagluQN22ibJMvG8op7q13iaFByEO3bwLoicFPml0RzzaAvrAQ3PJZCkloMwoLZbG9HTibP1vgic1g/640?wx_fmt=jpeg&from=appmsg "")  
  
图：需要批准APK安装的步骤  
  
**尽管威胁行为者声称漏洞可“一键式”利用。但是，由于需要多次点击、多个步骤，以及特定设置才能在受害者设备上执行恶意有效负载，这大大降低了攻击成功的风险。**  
ESET在Telegram的网页客户端和Telegram桌面版上测试了该漏洞，发现它在这些平台上不起作用，因为有效负载被视为MP4视频文件。  
Telegram在10.14.5版中对漏洞进行了修复，现在能正确显示APK文件的预览，因此接收者不再会被伪装成视频的文件所欺骗。  
如果您最近通过Telegram收到要求使用外部应用播放的视频文件，请使用移动安全套件扫描文件系统，以定位并移除设备上的有效负载。  
通常，Telegram视频文件存储在“/storage/emulated/0/Telegram/Telegram Video/”（内部存储）或“/storage//Telegram/Telegram Video/”（外部存储）中。   
  
  
**参考资料：bleepingcomputer.com**  
  
  
  
点击下方卡片关注我们，  
带你一起读懂网络安全 ↓  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibweTPiagluQN22ibJMvG8op7qtcVvR6tVdbXBcBHXOXcbgry3bYrYpwlgun3MibjDsYf7Aiachv7WDEag/640?wx_fmt=png&from=appmsg "")  
  
编辑：席沐沂  
  
审核：秦川原  
  
来源：安全内参  
  
