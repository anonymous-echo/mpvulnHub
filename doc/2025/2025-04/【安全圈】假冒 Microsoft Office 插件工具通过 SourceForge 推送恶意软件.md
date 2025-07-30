#  【安全圈】假冒 Microsoft Office 插件工具通过 SourceForge 推送恶意软件   
 安全圈   2025-04-09 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
恶意软件  
  
  
![黑客](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylialUJ3XzfEdkAGzyibyrGhS8fFSUUpkBupiaXciawl3SYN567upJT7iaicaR9w3QJicyprVc39ExNORia1WA/640?wx_fmt=jpeg&from=appmsg "")  
  
威胁行为者正在滥用 SourceForge 分发伪造的 Microsoft 插件，这些插件会在受害者的计算机上安装恶意软件，以挖掘和窃取加密货币。  
  
SourceForge.net 是一个合法的软件托管和分发平台，还支持版本控制、错误跟踪和专门的论坛/wiki，因此在开源项目社区中非常受欢迎。  
  
尽管其开放的项目提交模型为滥用提供了很大的空间，但实际上看到通过它传播的恶意软件的情况却很少见。  
  
卡巴斯基发现的新活动已影响超过 4,604 个系统，其中大部分位于俄罗斯。  
  
尽管该恶意项目在 SourceForge 上已不再可用，但卡巴斯基表示该项目已被搜索引擎编入索引，并带来了搜索“办公插件”或类似内容的用户流量。  
  
![搜索结果中托管恶意软件的 SourceForge 页面](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylialUJ3XzfEdkAGzyibyrGhS8oKodIALtBFcA7bVHkMMp5yDQQFuLZ4PrSYCc3mLSsicZKzyM6Y9qGTA/640?wx_fmt=png&from=appmsg "")  
  
## 假冒 Office 加载项  
##   
  
“officepackage”项目将自己展示为 Office 插件开发工具的集合，其描述和文件是 GitHub 上合法 Microsoft 项目“Office-Addin-Scripts”的副本。  
  
![恶意项目（左）和合法工具（右）](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylialUJ3XzfEdkAGzyibyrGhS8qCyfCjajb18CZ4bvicn0lKuibFVwUYdicYyic3Q6oEggqe2bxGyKia5yGow/640?wx_fmt=png&from=appmsg "")  
  
  
然而，当用户在 Google 搜索（和其他引擎）上搜索办公插件时，他们会得到指向“officepackage.sourceforge.io”的结果，该结果由 SourceForge 为项目所有者提供的单独的网络托管功能提供支持。  
  
该页面模仿合法的开发人员工具页面，显示“Office 插件”和“下载”按钮。如果点击任何一个按钮，受害者就会收到一个 ZIP 文件，其中包含受密码保护的存档 (installer.zip) 和带有密码的文本文件。  
  
![传播恶意软件的网站](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylialUJ3XzfEdkAGzyibyrGhS8njvWpiaMkRIUIFGpVRZFjzibTz3KP0DVL08wcfKt3JibwcZYTSuPs3pOA/640?wx_fmt=png&from=appmsg "")  
  
  
该存档包含一个 MSI 文件 (installer.msi)，其大小被夸大到 700MB，以逃避 AV 扫描。运行它会释放“UnRAR.exe”和“51654.rar”，并执行一个 Visual Basic 脚本，该脚本从 GitHub 获取批处理脚本 (confvk.bat)。  
  
该脚本执行检查以确定它是否在模拟环境中运行以及哪些防病毒产品处于活动状态，然后下载另一个批处理脚本（confvz.bat）并解压 RAR 存档。  
  
confvz.bat 脚本通过修改注册表和添加 Windows 服务来建立持久性。  
  
RAR 文件包含一个 AutoIT 解释器 (Input.exe)、Netcat 反向 shell 工具 (ShellExperienceHost.exe) 和两个有效负载 (Icon.dll 和 Kape.dll)。  
  
![完整的感染链](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylialUJ3XzfEdkAGzyibyrGhS8PIicZJLibbWia9MNI3yo4asB2UeDqHdhYS0iao5tXcf3h1NUcibmALA9SKg/640?wx_fmt=png&from=appmsg "")  
  
  
这些 DLL 文件分别是加密货币挖矿程序和剪切程序。前者劫持机器的计算能力，为攻击者的账户挖掘加密货币，后者监视剪贴板中复制的加密货币地址，并将其替换为攻击者控制的地址。  
  
攻击者还通过 Telegram API 调用接收受感染系统的信息，并可以使用相同渠道向受感染的机器引入额外的有效载荷。  
  
这次活动是威胁行为者利用任何合法平台来获取虚假合法性并绕过保护的另一个例子。  
  
建议用户仅从他们可以验证的可信发布者那里下载软件，优先选择官方项目渠道（在本例中为 GitHub），并在执行之前使用最新的 AV 工具扫描所有下载的文件。  
  
更新 4/9 - BleepingComputer 收到了来自 SourceForge 总裁 Logan Abbott 的以下评论  
  
SourceForge 上没有托管任何恶意文件，也没有任何形式的违规行为。涉事恶意行为者和项目在被发现后几乎立即被删除。SourceForge.net（主网站，而非项目网站子域名）上的所有文件都经过恶意软件扫描，用户应该从那里下载文件。无论如何，我们已经采取了额外的安全措施，确保使用免费虚拟主机的项目网站将来无法链接到外部托管文件或使用可疑的重定向。—— Logan Abbott，SourceForge  
  
来源：  
https://www.bleepingcomputer.com/news/security/fake-microsoft-office-add-in-tools-push-malware-via-sourceforge/  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】#DeepSeek又崩了#](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068959&idx=1&sn=e9b5f893828331429dcbf677edf57f8b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客利用 Windows .RDP 文件进行恶意远程桌面连接](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068959&idx=2&sn=a6f70e9a667f3b234b235f4b7979f762&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客利用 VPS 托管提供商传播恶意软件并逃避检测](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068959&idx=3&sn=18af1323563184d43efe6a0254a9e5fc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Dell PowerProtect 系统漏洞可让远程攻击者执行任意命令](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068959&idx=4&sn=e57a187e3a257c344e9371d382cfa185&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
