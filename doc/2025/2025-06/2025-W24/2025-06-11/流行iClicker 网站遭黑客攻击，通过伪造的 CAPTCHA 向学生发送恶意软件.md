#  流行iClicker 网站遭黑客攻击，通过伪造的 CAPTCHA 向学生发送恶意软件  
Rhinoer  犀牛安全   2025-06-11 16:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rbct6wXmBOibZwj49c61ota5J4DqAcCS3lQrjj6fJw3G9XzgZ975QjAQ/640?wx_fmt=png&from=appmsg "")  
  
流行的学生参与平台 iClicker 的网站在一次 ClickFix 攻击中遭到入侵，该攻击使用虚假的 CAPTCHA 提示诱骗学生和教师在其设备上安装恶意软件。  
  
iClicker 是麦克米伦的子公司，是一款数字课堂工具，允许教师点名、实时提问或进行调查，并跟踪学生的参与度。它被美国各大专院校的 5000 名教师和 700 万名学生广泛使用，其中包括密歇根大学、佛罗里达大学和加州的大学。  
  
根据密歇根大学安全计算团队的安全警报，iClicker 网站在 2025 年 4 月 12 日至 4 月 16 日期间遭到黑客攻击，显示一个伪造的 CAPTCHA，指示用户按“我不是机器人”来验证自己。  
  
然而，当访问者点击验证提示时，PowerShell 脚本就会被悄悄复制到 Windows 剪贴板中，这就是所谓的“ClickFix”社会工程攻击。  
  
然后，CAPTCHA 会指示用户打开 Windows 运行对话框 (Win + R)，将 PowerShell 脚本 (Ctrl + V) 粘贴到其中，然后按Enter执行以验证自己。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rT2nJZx06ZxnRpmtShYv3cneVqslkqghMmAnw1rBlVTBFT7KRVWW4Zg/640?wx_fmt=png&from=appmsg "")  
  
虽然 ClickFix 攻击不再在 iClicker 的网站上运行，但Reddit 上的一个人在Any.Run上启动了该命令，揭示了执行的 PowerShell 有效负载。  
  
iClicker 攻击中使用的 PowerShell 命令经过了高度混淆，但在执行时，它会连接到 http://67.217.228[.]14:8080 的远程服务器以检索将要执行的另一个 PowerShell 脚本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rqbuS87EcC6CMryj0kqlpHicRK1icoOBnUZicJcQichdESrOzQNPrkibdgpA/640?wx_fmt=png&from=appmsg "")  
  
不幸的是，我们不知道最终安装了什么恶意软件，因为检索到的 PowerShell 脚本根据访问者的类型而不同。  
  
对于目标访客，它会发送一个脚本，将恶意软件下载到计算机上。密歇根大学表示，该恶意软件允许威胁行为者完全访问受感染的设备。  
  
对于那些没有被针对的对象，例如恶意软件分析沙箱，该脚本将下载并运行合法的 Microsoft Visual C++ Redistributable，如下所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rXeKhQGwgq7PFRbP0DzeZPnibvGFGjBITbgkYc1s4ViamwVF0LhbY6u7g/640?wx_fmt=png&from=appmsg "")  
  
ClickFix 攻击已成为一种广泛的社会工程攻击，已被用于众多恶意软件活动，包括伪装成 Cloudflare CAPTCHA、Google Meet和网络浏览器错误的攻击。  
  
从过去的活动来看，此次攻击很可能传播了一个信息窃取程序，它可以从 Google Chrome、Microsoft Edge、Mozilla Firefox 和其他 Chromium 浏览器窃取 cookie、凭据、密码、信用卡和浏览历史记录。  
  
此类恶意软件还可以窃取加密货币钱包、私钥和 可能包含敏感信息的文本文件，例如名为 seed.txt、pass.txt、ledger.txt、trezor.txt、metamask.txt、bitcoin.txt、words、wallet.txt、*.txt 和 *.pdf 的文件。  
  
这些数据被收集到一个档案中并发送回给攻击者，攻击者可以利用这些信息进行进一步的攻击或在网络犯罪市场上出售。  
  
被盗数据还可能被用于大规模入侵，最终引发勒索软件攻击。由于此次攻击的目标是大学生和教师，其目标可能是窃取凭证，从而对高校网络进行攻击。  
  
BleepingComputer 本周多次联系 MacMillan 询问有关此次攻击的问题，但尚未得到回复。  
  
然而，BleepingComputer 后来发现，iClicker 于 5 月 6 日在其网站上发布了安全公告，但 <meta name='robots' content='noindex, nofollow' />在页面的 HTML 中包含了一个标签，导致该文档无法被搜索引擎编入索引，从而使查找有关该事件的信息变得更加困难。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rw2fzQGOcX3r8MGm1GEG2efBricn4xzibTUu4IReGnwhOegYTurVmWMug/640?wx_fmt=png&from=appmsg "")  
  
iClicker 的安全公告中写道：“我们最近解决了影响 iClicker 登陆页面 (iClicker.com) 的事件。重要的是，iClicker 的数据、应用程序或操作均未受到影响，并且 iClicker 登陆页面上已发现的漏洞已得到解决。”  
  
事情是这样的：一个无关的第三方在用户登录我们网站上的 iClicker 之前，在我们的 iClicker 登录页面上放置了一个虚假的验证码。该第三方希望诱使用户点击该虚假验证码，这种行为类似于我们最近在钓鱼邮件中经常遇到的情况。  
  
“出于谨慎考虑，我们建议 4 月 12 日至 4 月 16 日期间在我们的网站上遇到并点击虚假验证码的任何教职员工或学生都应运行安全软件，以确保他们的设备受到保护。”  
  
在网站被黑客入侵时访问 iClicker.com 并按照虚假 CAPTCHA 指令的用户应立即更改其 iClicker 密码，如果执行了该命令，则将其计算机上存储的所有密码更改为每个网站的唯一密码。  
  
为了解决这个问题，建议您使用 BitWarden 或 1Password 等密码管理器。  
  
值得注意的是，通过移动应用程序访问 iClicker 或未遇到假 CAPTCHA 的用户不会受到攻击的风险。  
  
  
信息来源：B  
leepingComputer  
  
