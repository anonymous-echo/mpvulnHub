#  Telegram Desktop RCE . "pywz" VS "pyzw" 开发的手抖经典案例   
David_Jou  Ots安全   2024-04-13 09:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
因为这个RCE近几天沸沸扬扬  
  
前脚刚  
CertiK 发布告警：[安全告警 - Telegram 网传RCE](http://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247506102&idx=1&sn=8ff8078f81ac1c055305104f2948b803&chksm=9bad91fdacda18ebe1e1032c8c1ebe1de37170e794f6e396038089b13ac9e6f3f01a1160313a&scene=21#wechat_redirect)  
  
  
后脚官方发布消息可能不可靠：[Telegram 网传RCE - 官方回应](http://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247506182&idx=1&sn=cada28147393750a176a8bf29bc2bb36&chksm=9bad904dacda195bcc2b427431ba925578444f4add152685fd235ff629bbdf8e8f5eaf25ffb1&scene=21#wechat_redirect)  
  
  
  
最后因为开发者的手抖，成了这样：  
  
https://github.com/telegramdesktop/tdesktop/pull/27737/commits/effad980f712cd1a4e8cee4fca42193fe5a612de  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacdGxU2CGEM0lwc9LbT1WibIGvDNvZib6bzCBXEtMgMrBREMbd6Z8HEnAJ3tqpDCoJAsT0PM7f93iaqA/640?wx_fmt=png&from=appmsg "")  
  
随后@VulkeyChen师傅根据@im23pds的帖子进行了回答  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacdGxU2CGEM0lwc9LbT1WibIkeTBhsFibibGmFzibECcVh3Apr9MdJaEJ3dls0o00NACCbeBbHaPzdsSA/640?wx_fmt=png&from=appmsg "")  
  
随后在项目中的一项评论发现了重要的一点：  
  
https://github.com/telegramdesktop/tdesktop/pull/27737  
  
Windows 上正确的 python zipapp 扩展是 pyzw，此拼写错误可能会导致在客户端设备中执行代码而没有适当的警告  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacdGxU2CGEM0lwc9LbT1WibICibqgic36QmQAz5AHXQ0qbGnHheGKd6sN8vlgnZ3aOicb8WscJY2tibgqQ/640?wx_fmt=png&from=appmsg "")  
  
  
**复现过程：**  
  
这里使用了校长师傅的复现方式 - 或自行移步校长公众号（干货很多）：  
  
[https://mp.weixin.qq.com/s/FoLdjtE2JvtB53HfY-8MIg](https://mp.weixin.qq.com/s?__biz=MzkyMzI3OTY4Mg==&mid=2247486612&idx=1&sn=502c0430b8f70d49bd56ffa794a0385f&scene=21#wechat_redirect)  
  
  
```
import subprocess
subprocess.run("calc.exe")
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacdGxU2CGEM0lwc9LbT1WibI5Yq3lxYynCRv19FwBwxKUtPo2xY3OhM4FTBkofPSPbicLsXlIwJDrEA/640?wx_fmt=png&from=appmsg "")  
  
这里就有一个重要，就是利用难度的问题，曾哥也评论了相关需要Python环境支撑，才能RCE！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacdGxU2CGEM0lwc9LbT1WibI9v0dhdl913SE7BkCvYwKJhuYXZayyOibPK8jLQ2hZ8f0YWZCWZ4oZSQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
随后尝试python2和python3的环境，也只是函数之差，这些也并不重要，只是小小的细节问题。（.pywz文件通常是需要对此类的文件设置默认python为打开模式）要不然会提示使用什么方式打开，  
包括在  
Telegram也会提示。  
  
  
python2  
```
# -*- coding: utf-8 -*-

import subprocess

# 打开计算器
subprocess.call("calc.exe")
```  
  
python3  
```
import subprocess

# 打开计算器
subprocess.run("calc.exe")
```  
  
在曾哥团队群聊里面也有人问了，MP4格式是怎么弄的，校长的文章中也是提示到使用API机器人转发，变成MP4。  
  
  
**我们看看下面的这段代码内容：**  
  
这段代码是一个Node.js脚本，用于创建一个Telegram机器人（bot），当收到指定命令"/video"时，它会向指定的聊天ID发送一个视频文件。代码中使用了node-telegram-bot-api库来操作Telegram Bot API，并且使用了fs模块来读取文件。将读取指定路径下的文件（"/home/user/download.pyzw"），并将其作为视频文件发送给指定的聊天ID，然后就是我们看到的MP4格式RCE了。  
  
  
**帖子在这，做了缩短：**  
  
http://dz4fp.osxo.cn/8a  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tacdGxU2CGEM0lwc9LbT1WibIeCBOUicicNn1NSf8VfrVOH0yH15kWMQE8VarXcEON7aAYGWcNpiaQ3pZw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
关于API机器这步骤也是尝试了搭建转发机器人，因为没有部署过Telegram的机器，也是用的BotFather和cloudflare测试和改了好几遍弄成一坨屎直接放弃了。  
  
  
最后找到了这个项目https://github.com/yagop/node-telegram-bot-api。最后写到这里我也是看到校长的那篇文章尾部是说：做了限制，但是对于整个RCE完整复现还是得在机器人上花费时间，那么先到这里吧！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacdGxU2CGEM0lwc9LbT1WibIwvmmJma1qicYWqTTL4tIuWUEolnibAejLlGr2cP3jLqbKA1wqRjfoiawQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
推荐一波：  
  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
