#  小米在 Pwn2Own Toronto 2023 大赛前修补了 RCE 漏洞，并在大赛结束后删除了补丁   
原创 Pwn2Own  安全之眼SecEye   2024-08-23 21:37  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2lO3vZg4Fdl5mqjI4qwPQkFzIO015f7lQc8kTmHXyT9HvczHTD2y31JA/640?wx_fmt=png&from=appmsg "")  
  
在 Pwn2Own Toronto 2023 竞赛期间，列出了几个类别和设备供研究人员瞄准。至于移动设备，有 Apple iPhone 14、Google Pixel 7、三星 Galaxy S23 和小米 13 Pro。他们每个人都列出了自己的现金奖励和 Pwn 积分。研究人员 Ken Gannon 和 Llyes Beghdadi 在比赛中选择了小米 13 Pro 设备进行利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2lVzsTdOS6FA8LeWbb1lKDvJicW2iccvbAIGicx7Wticu8iccwB8tgpNxQU1w/640?wx_fmt=png&from=appmsg "")  
  
他们花了大约 97 天的时间，发现了小米的某些行为和一些安全漏洞 (CVE-2023-26324)。其中一个有趣的发现是，小米设备的行为会根据设备所在地区而有所不同。例如，如果设备地区设置为英国，则该设备会启用“ GetApps ”应用程序。  
  
但是，如果将设备区域设置为美国，则设备没有“ GetApps ”（小米的应用商店）。同样，对于俄罗斯地区，启用了 Yandex 浏览器，对于西班牙地区启用了“ Opera ”，对于印度尼西亚地区启用了 WhatsApp。这证明了小米 13 Pro 根据设备所在地区对不同安装的应用程序采取不同的行为。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2lgP5rPDt9XDSusOYUAoCJUJhVUia9w1yuhWEkSBCaLGtI2R0bg9oMVPQ/640?wx_fmt=png&from=appmsg "")  
  
以此为基本利用目标，研究人员选择将目标锁定在 400 多个应用程序上，并优先考虑小米开发的应用程序。经过 22 天的研究，他们发现他们能够以三种不同的方式利用“GetApps ”，从而强制安装应用程序。此外，他们只需用户点击恶意超链接即可安装任何应用程序。  
## 技术分析 – Pwn2Own 前几天  
  
DEFCON 32 上发布的研究报告显示，三项漏洞利用中的两项涉及使用**Browsable Intent 代码***，该代码会在用户点击链接时安装指定的应用程序。第三项漏洞利用与具有 JS 界面的“ GetApps* ”的 WebView 有关。  
  
JS 接口函数有两个，一个是install （在未经用户同意的情况下安装“ GetApps ”上的任何应用程序）和一个 openApp（在未经用户同意的情况下打开特定应用程序）。此外，小米还在 WebView 中实现了 URL 验证，因为他们使用了两个高权限的 JS 函数。  
  
此验证包括https://协议（该协议必须具有白名单中的域）和file:///协议（该协议必须是/data/data/com.xiaomi.mipicks/files/web-res-XXX/中存在的文件，该文件只能由“ GetApps ”应用程序访问）。  
## 漏洞利用方法  
  
为了利用这一流程，研究人员制定了一个包含以下 4 个步骤的计划：  
- 启动 WebView 并加载有效的 URL  
  
- 注入自定义 JS 代码  
  
- 执行两个 JS 接口函数，从 GetApps 安装恶意应用程序并启动它  
  
- 在设备上获取远程代码执行  
  
### 启动 WebView  
  
为了启动 WebView，研究人员使用了 JoinActivity 类，该类可以通过 Browsable Intent 启动。简单来说，Browsable Intent 允许 URL 通过 HTML 页面中的超链接启动 Android 应用程序。由于此 JoinActivity 使用 URL，因此研究人员能够指定 URL 并启动 WebView  
### 注入 JS 代码  
  
注入 JS 代码有两种方式：一是渗透测试白名单域并找到可用的漏洞，二是分析 web-res-XXX 中的文件以查找用户输入问题。然而，研究人员选择分析包含 HTML 和 JS 文件的 web-res-XXX 文件。  
  
虽然一些 JS 文件通过 GET 参数接受用户输入，但它们集成了输入清理功能。清理功能是专门为检查潜在的 XSS 负载而创建的。  
  
然而，我们发现一个特定的 JS 文件缺乏清理。该文件是 integration-dialogpage.chunk.js，它加载了 integration-dialog-page.html。  
  
此外，研究人员还发现该 HTML 文件中存在 DOM XSS，以及一些成功的 DOM XSS 负载。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2luqnxTSxwXZ5N4xBib8vODapZFERJIsu46gLDiadZefuV4VsFQwEzricsw/640?wx_fmt=png&from=appmsg "")  
### 执行 JS 函数来安装并启动应用程序  
  
他们使用 DOM XSS 有效载荷执行 JS 接口并调用特权 WebView。此外，他们还注入了一个有效载荷，其中包含通过“ GetApps ”安装哪个应用程序的参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2lAb4BdKXuiaaHdRR9WYUoharJaWGEXCtfD9MN4g6b5KdfVVDNECLObpw/640?wx_fmt=png&from=appmsg "")  
  
为了测试目的，研究人员上传了一个名为“ Sunfish ”的应用程序，它是“ Drozer ”的特殊版本，在应用程序启动时会启动一个监听绑定shell。  
### 在设备上获取远程代码执行  
  
在设备上安装并启动Sunfish应用程序后，研究人员获得了反向shell。  
  
## 小米的补丁攻击  
  
在 Pwn2Own 比赛开始前两周，小米发布了一个大型补丁，修复了这个“GetApps”漏洞。然而，该漏洞在英国地区仍然有效。这并不是小米补丁的终结。  
  
在此次大规模补丁更新一周后，小米发布了另一个补丁，删除了漏洞利用所需的关键文件integral-dialog-page.html和.js文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2lXHMXldyvbedka1RdYSjovtQN3GxkJ3fQOz6m9NGnAg8P35aNibwBEicQ/640?wx_fmt=png&from=appmsg "")  
  
不过，此次更新仅适用于已修补的设备，这意味着该文件将在小米Pro 13的旧版本上可用。但小米有其他想法。  
  
在Pwn2Own比赛开始前3天，小米发布了另一个补丁，添加了拦截JoinActivity的代码，从而阻止从包括小米和谷歌Chrome浏览器在内的多个来源启动Browsable Intent（但不包括“ Opera ”浏览器或“Yandex”浏览器）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2l0Kn6DdOckWWp8YSGic98viaBqLyQia2LQOJ3o2eLhol6a0EPnz6ncCrMg/640?wx_fmt=png&from=appmsg "")  
  
因此，研究人员告知 Pwn2Own 团队，他们将使用专门针对西班牙地区的设备。此外，Pwn2Own 还允许安装除 Starfish 之外的任何应用程序。  
  
尚不清楚小米如何知道所有漏洞即将被利用（也许是 Pwn2Own 中的“内部威胁”？）。在 Pwn2Own 比赛的第二天，小米又发起了一次补丁攻击，该攻击禁用了从其“ GetApps ”商店安装应用程序的功能。  
  
另一位针对同一款小米设备的研究人员表示，“向小米团队致敬，他们证明你可以在几个小时内完全远程修补 RCE 漏洞（同时还可以让你的旗舰设备在全国各地变砖），只要你这么做是出于恶意，而不是因为你真的关心修复问题”。  
## 等一下，他们删除了那个补丁吗？  
  
小米完美策划了这次攻击，他们在 Pwn2Own 比赛后删除了“GetApps”中的浏览器阻止代码，这使得攻击可以方便地再次发生。这种公司行为使研究人员无法从小米那里获得 CVE。此外，他们还发布了针对这些漏洞的安全公告。  
  
然而，ZDI 向他们提供了 CVE 编号，在他们与小米确认后，小米分配了一个 CVE。有两个团队针对小米设备，分别是 NCCGroup 团队（Ken Gannon (@Yogehi) 和 LLyes Beghdadi (@040xZx)）和拥有四名团队成员的 Viettel 团队。事实上，NCC Group 并未因该漏洞获得任何荣誉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lnWLbmMAUaCpYVZQo7NJ2lDU58iaf8udVkhQtaUatm9wVT7JhLtaMich8ibU26gVLLIG3pP8CaI7iazQ/640?wx_fmt=png&from=appmsg "")  
  
小米安全公告未对研究人员做出说明（来源：  
第 32 级警戒  
)  
  
企业和供应商需要注意的是，研究人员花费大量时间来寻找漏洞，如果被威胁行为者利用，可能会毁掉你的整个声誉。  
  
另一个需要注意的是，此特定漏洞允许威胁行为者只需制作恶意链接并在 GetApps 应用商店上传恶意应用程序即可访问受害者设备。  
  
像这样的一键式漏洞是每个黑帽黑客都会掌握的，并利用全球多个受害者。仅在比赛期间修复漏洞并不是好做法。因此，我们建议所有供应商为安全研究人员提供支持并给予适当奖励。  
  
翻译自：https://hackhunting.com/2024/08/22/xiaomi-patched-an-rce-vulnerability-before-pwn2own-toronto-2023-and-removed-the-patch-afterwards/ ,  
仅做分享，文章观点不代表本公众号观点。  
  
关注我们：  
  
  
