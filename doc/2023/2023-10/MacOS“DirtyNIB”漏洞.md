#  MacOS“DirtyNIB”漏洞   
xiaohui  嘶吼专业版   2023-10-26 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
在这篇文章中，我们将关注macOS Sonoma中的一个漏洞，该漏洞已经存在很长时间了，直到今天仍然活跃。2023年6月5日，苹果在WWDC 2023开发者大会上发布macOS Sonoma开发者预览版，macOS Sonoma 新版最大的亮点在于支持桌面端的小部件，以及允许用户自定义壁纸作为屏保。用户在打开窗口之后，小部件会淡入背景。另外 Mac 和 iPhone 如果连接到相同 Wi-Fi 网络，可以访问来自 iPhone 的小部件，小部件也是交互式的。  
  
兼容macOS Sonoma机型：  
  
2019 年以及后续的 iMac 机型；  
  
2019 年以及后续的 Mac Pro 机型；  
  
2017 年以及后续的 iMac Pro 机型；  
  
2022 年以及后续的 Mac Studio；  
  
2018 年以及后续的 MacBook Air 机型；  
  
2018 年以及后续的 Mac mini 机型；  
  
2018 年以及后续的 MacBook Pro 机型。  
# 漏洞分析  
  
macOS中的图形应用程序通常会有一个由NIB文件定义的UI。你之前可能在XCode中以XIB的形式处理过这些文件，这些文件后来在发布期间被编译为NIB，NIB文件是应用程序使用的接口对象集及其关系的静态存储表示，可以在需要时有效地将其放入内存，从而减少开发时间并使针对不同市场的应用程序本地化变得更加容易。  
  
Mac OS X的应用程序虽然不需要使用NIB文件即可运行，但是，NIB文件在OS X和iOS创建应用程序中起着重要的作用。使用NIB文件，你可以使用Xcode以图形方式创建和操作用户界面（而不是以编程方式），可以立即查看更改的结果，快速尝试不同的布局和配置，也可以稍后更改用户界面的许多方面，而无需重写任何代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlIz9Fk6ZKa9YfyjNbib2ZAHyMsdkPperQy0PZNyTYiaueGOy7uI4jHmng/640?wx_fmt=png "")  
  
事实证明，一旦Gatekeeper验证了应用程序，在Bundle文件夹中交换NIB文件并不会使访问权限失效。所以你可以在部署应用程序后重新构建它，实际上，通过修改后的NIB执行代码非常简单，而苹果喜欢在其应用程序中添加私有权限。  
# DirtyNIB  
  
“DirtyNIB”是一种从NIB文件中获得代码执行的简单方法。  
  
首先，我们需要创建一个新的NIB文件，我们将使用XCode进行大部分构建，向接口添加一个Object，并将类设置为NSAppleScript：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlML73ZKE6daq9iaynRwt9libWR718cPLDqnURCXfAbBcgmLRW8DB7QpXw/640?wx_fmt=png "")  
  
对于Object，我们需要设置初始source属性，我们可以使用用户定义的运行时属性：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nloJzIR1eYdtGhSGYUl7gNtwzT1Scsa76wCOGfxvjf8jNbjr8hdCYNOQ/640?wx_fmt=png "")  
  
这设置了我们的代码执行gadget，它将根据请求运行AppleScript。为了真正触发AppleScript的执行，我们现在只需添加一个按钮，该按钮将绑定到我们刚刚创建的Apple Script对象，并将调用executeAndReturnError: selector：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlElhR7SLTBiajib3iaydib1iaTfNZ0h0RrTpNFYwsrMVMWWS4ck6Pxa3eWFg/640?wx_fmt=png "")  
  
为了进行测试，使用的Apple Script如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlc5PBrISdz0FTkBxrlqsFWUH1yNSXNb5hZh6WicQG110RZ1gy3ziaJFcA/640?wx_fmt=jpeg "")  
  
如果我们在XCode调试器中运行此脚本并点击按钮，结果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlDGCm8oxrEs1D5PU6icZ7BBhIJkKjZ42HQ1ZEibXY2Wq93PMibN9JNlOGg/640?wx_fmt=png "")  
  
有了从NIB执行任意AppleScript代码的能力，接下来需要选择Pages作为我们的初始目标，它是一个苹果应用程序。  
  
我们首先将应用程序复制到/tmp/中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlI8g3KnfJkr7JLN1R6oGYXIr7t8MN1YJcCYrJWT3MVfZz2s0TnVEImg/640?wx_fmt=jpeg "")  
  
然后，我们将启动应用程序以避免任何Gatekeeper漏洞，并允许缓存内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlflLSN0gAwvFSfnKulhCelLOjWaS6lxpnxL80dxmL7P5M7mqrVcBS9g/640?wx_fmt=jpeg "")  
  
在第一次启动并终止应用程序后，我们需要用DirtyNIB文件覆盖现有的NIB文件。出于演示目的，我们将覆盖About Panel NIB，我们可以控制执行：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlp1JqcNfwKyUzEd9I8F8a3TKIct2fEHeicrqNdNXrunCrKhbTp6mNXzQ/640?wx_fmt=jpeg "")  
  
一旦我们重写了NIB文件，就可以通过选择About菜单项来触发执行：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlWmxWaUMeiaiaUC5kkthmbN1uCVP83Dk4PraO8ThricAynnQ5oIUh2GFibw/640?wx_fmt=png "")  
  
如果仔细看一下Pages，我们会发现它有一个私有权限，可以访问用户的照片：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlqaYsz7UNkQqNaUbgWHriaFydOoYko0l9XpnubnqKgcIFz37HTRCekbA/640?wx_fmt=png "")  
  
因此，我们可以通过修改AppleScript来测试POC，这样就可以在没有提示的情况下从用户那里窃取照片：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nl8uHfzZ68NyPU5c8WgZpOmg7J9QbaKkuHMibxiaIHq7jnyAwicJVgdMibFg/640?wx_fmt=jpeg "")  
  
在进入有趣的内容之前，让我们看看macOS后续版本中引入的一些注意事项。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wpkib3J60o287jwk8LWD9icmgWlahS21WB8lECGmeJOXSiafEcxpJYOHrph36wNX7lyjD7jckJk6EMZ4bGp59RNrA/640?wx_fmt=png "")  
  
macOS Ventura  
  
macOS Ventura新版本增加了强大生产力工具、全新连续互通功能，让 Mac 体验更胜以往。  
  
有了它，就可以Launch Constraint。那么，什么是Launch Constraint？这就是苹果阻止我们使用之前技巧的方法，即复制平台Bundle文件夹及其对/tmp的授权和修改资产。  
  
让我们快速回顾一下如何解析macOS中的Launch Constraint列表。包含可信哈希值的数据库位于：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlsW2icKYXsmxGsH1Dp4FUdJ06icdWGjYFABQCnZ750juPfOqIeP8n7K1Q/640?wx_fmt=jpeg "")  
  
由于缓存采用img4格式，我们首先需要使用img4tool提取它：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nl35YeF9odwnshDgB232uTKNGvkJSFzPZMQpbksPz1q8PiaLeibxct6hmA/640?wx_fmt=png "")  
  
提取缓存后，我们需要解析内容。为此，我们需要创建了一个脚本extract_trustcache.py，具体过程可以在这里找到，它将为我们提供CDHASH和ConstraintCategory列表：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlmIUeyUtQ1o36BkDItfBvsN6qcicWaGaL3PIa8sGUU9dop9Zv21cYcEA/640?wx_fmt=png "")  
  
如果我们想知道每个类别的含义，我们可以参考Linus Henze的Gist。  
  
现在，我们需要搜索值为0的Launch Constraint，这允许我们复制内容进行修改。当然有很多，但为了简单起见，我在macOS Ventura上找到的是：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlufMDPok8CrltpfeNSc98OCGKiarHRP9iabtYibN8JkhXv6icxeL0fvAs4g/640?wx_fmt=jpeg "")  
  
在这些二进制文件中，我们现在需要定位值得劫持的目标范围。在搜索时，在MobileDeviceUpdater.app中发现了有趣的内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlLxRdjjh43gpspQqJiak1r6aaD9S2XUkpXYzKkbwRINU0DhGTYfts2mQ/640?wx_fmt=png "")  
  
不幸的是，由于在PkgKit中有额外的要求，前面演示的漏洞不能再被利用。  
# 寻找新的目标  
  
由于“Launch Constraint”，因此操作系统应用程序不再工作。所以，我们需要搜索其他具有授权的苹果二进制文件。在Additional_Tools_for_Xcode_15_Release_Candidate.dmg中可以找到一组有趣的二进制文件，该软件可以从Apple Developer网站下载。  
  
具体来说，我们将从DMG获得CarPlay Simulator.appBundle文件夹，该Bundle文件夹可以在不提示的情况下通过麦克风录制：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nl0hK6P3jZ8tuu3x1riaibPgMr3WdcUbAbZTB4wBBcj1yMe6IdVl4BERYg/640?wx_fmt=png "")  
  
要使用DirtyNib文件进行实际录制，我们将使用下面的AppleScript：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlibOiaYkRvMJo7BHUaNTzTgUMFhNuXZObicAiaTQ7iam1fl8OspICbtOgpzQ/640?wx_fmt=jpeg "")  
  
以下在AppleScript中引用的序列化设置需要写入/tmp/output.plist：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlahZoXZAsRUGvic5PXlH7p2iafAXPfyD1REqG20ibC2GVct2MIpibkzOqqA/640?wx_fmt=jpeg "")  
  
当组合在一起时，访问麦克风TCC权限将意味着我们：  
  
1.将CarPlay Simulator.app的副本复制到/tmp/；  
  
2.启动CarPlay Simulator.app以在Gatekeeper中  
缓存；  
  
3.用Dirty.nib文件重写  
  
Contents/Resources/Base.lproj/MainMenu.nib；  
  
4.再次启动CarPlay Simulator.app。  
  
当在没有提示用户的情况下按下按钮时，这应该会启动使用TCCServiceMicrophone权限的麦克风录制：  
  
现在漏洞利用还没有完成，在Sonoma，我们还有一些障碍需要解决，因为还有对未经许可访问应用程序Bundle文件夹内容的新限制。  
  
幸运的是，可以通过以下6个步骤，继续利用：  
  
1.将CarPlay Simulator.app的副本复制到/tmp/；  
  
2.将/tmp/Carplay Simulator.app/Contents重命名为/tmp/Car Play Simulator.app/NotCon；  
  
3.启动二进制/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay模拟器以在Gatekeeper中缓存；  
  
4.用Dirty.nib文件重写NotCon/Resources/Base.lproj/MainMenu.nib；  
  
5.重命名为/tmp/CarPlay Simulator.app/Contents；  
  
6.再次启动CarPlay Simulator.app。  
  
这应该足以绕过新的保护措施并启动Dirty.nib漏洞利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlaRXbo42JVhk9bUWFB1l5aiaLX9acvoa2qEXCznEs76WYSazm6KWsckg/640?wx_fmt=png "")  
  
以上是我们如何应  
用此漏洞的一个示例，显然，这将适用于以下任何应用程序：  
  
1.拥有你想要劫持的权限；  
  
2.适用于新的Launch Constraint环境。  
  
例如，许多应用程序都带有值得探索的 keychain-access-groups。iOS的keychain服务提供了一种安全的保存私密信息（密码，序列号，证书等）的方式，每个ios程序都有一个独立的keychain存储。相对于NSUserDefaults、文件保存等一般方式，keychain保存更为安全，而且keychain里保存的信息不会因App被删除而丢失。钥匙串以储存在文件系统中的 SQLite 数据库的形式实现，而且数据库只有一个，securityd 监控程序决定每个进程或 App 可以访问哪些钥匙串项。钥匙串访问 API 将生成对监控程序的调用，从而查询 App 的“keychain-access-groups”、“application-identifier”和“application-group”权限。访问组允许在 App 之间共享钥匙串项，而非将访问权限限制于单个进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlwGc4FbNQCiczAOjM8R3rSaVLR59u96o6D6jgI3jFfMxLwyJmOe6ZXsA/640?wx_fmt=png "")  
  
最困难的部分将是弄清楚如何让AppleScript真正发挥作用。AppleScript 是远程桌面中的强大自动工具。  
  
AppleScript 是内建在 macOS 中的强大且通用的脚本语言，你可以配合 AppleScript 使用远程桌面来创建快捷键、自动执行重复任务或甚至制作可以节省您大量时间的自定 App。脚本可以根据用户交互或通过解析和分析数据、文稿或情况做出决定。  
  
AppleScript 是一种包含条件语句、比较和算术运算以及变量储存功能的完整语言。AppleScript 脚本包含发送给对象的命令，对象的范围可以很广，包括 App、脚本、窗口、设置或“访达”，这些对象可以接收特定命令集并使用所需操作响应。本质而言，脚本将告诉 App（此处为远程桌面）完成某个任务或取回信息，通过使用条件语句，您可以向脚本提供决定功能；通过定义变量，可以向脚本提供内存。  
  
本文中使用的XIB文件可以在这里找到。  
  
我们第一次向苹果报告这个漏洞是在2021年11月，经过多次确认，该漏洞曾被命名为CVE-2022-48505，现在它已经被修复。  
  
参考及来源：https://blog.xpnsec.com/dirtynib/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlAYQwrSLxDHEqUz9XtzGEib2icI7aWgIlYodOf3CrF08BEFAorz03HJxg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29KbM3Pj7HWYxwTyCcmC5nlGSWEUT3vDAdmI8pgVOUk7J6nqajkfBTibOfKX692adsIMdODa3eiazQg/640?wx_fmt=png "")  
  
  
