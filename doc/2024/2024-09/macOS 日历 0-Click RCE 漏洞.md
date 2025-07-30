#  macOS 日历 0-Click RCE 漏洞   
Mikko Kenttälä  合规渗透   2024-09-20 17:38  
  
from：Mikko Kenttälä  
  
我在 macOS 日历中发现了一个零点击漏洞，该漏洞允许攻击者在日历沙箱环境中添加或删除任意文件。这可能会导致许多不好的事情，包括恶意代码执行，这些代码可以与照片安全保护规避相结合，从而危及用户的敏感照片 iCloud 照片数据。Apple 已修复2022 年 10 月至 2023 年 9 月期间的所有漏洞。  
  
如果你想看我关于这个的演示视频，你可以查看我的 Disobey 2024 演示：如果您想观看我的演示视频，可以查看我的《Disobey 2024》演示： https://www.youtube.com/watch? v=9NlQXLLQrvk  
#   
  
第 1 阶段：日历中的任意文件写入和删除漏洞 (CVE-2022–46723)  
攻击者可以向受害者发送包含文件附件的恶意日历邀请。附件的文件名未正确清理。攻击者可利用此漏洞，通过在 ATTACH 部分中设置文件的任意路径，使用“FILENAME=../../../PoC.txt”。攻击者可以向受害者发送包含文件附件的恶意日历邀请。附件的文件名未正确清理。攻击者可以利用此漏洞通过在 ATTACH 部分中设置文件的任意路径来成功进行目录遍历攻击：“FILENAME=../../../PoC.txt”。  
  
这将导致文件添加到 ~/Library/Calendar/PoC.txt 而不是 ~/Library/Calendar/[CalendarID]/Attachments/[eventid]/ 。这将导致文件被添加到 ~/Library/Calendar/PoC.txt 而不是 ~/Library/Calendar/[CalendarID]/Attachments/[eventid]/ 。  
  
如果攻击者指定的文件已经存在，则指定的文件将以 “PoC.txt-2” 的名称保存。但是，如果攻击者发送的事件/附件稍后被删除，则原始名称 （PoC.txt） 的文件将被删除。此漏洞可用于从文件系统中删除现有文件（在文件系统“沙箱”内）。如果攻击者指定的文件已经存在，则指定的文件将以名称“PoC.txt-2”保存。但是，如果攻击者发送的事件/附件随后被删除，则原始名称 (PoC.txt) 的文件将被删除。该漏洞可用于从文件系统（文件系统“沙箱”内）中删除现有文件。  
  
漏洞似乎至少存在于最新的 macOS Montrey 12.5 中。MacOS 13.0 beta4 似乎不再容易受到攻击。该漏洞似乎至少存在于最新的 macOS Montrey 12.5 中。MacOS 13.0 beta4 似乎不再容易受到攻击。  
## 第2阶段：利用任意文件写入漏洞获得远程代码执行（RCE）  
  
当发现这个漏洞时，Ventura 即将被释放。可以利用 macOS 版本升级过程，通过 Calendar 中的“打开文件”功能获得远程代码执行。当这个漏洞被发现时，Ventura 即将发布。可以利用 macOS 版本升级过程通过日历中的“打开文件”功能获得远程代码执行。  
  
为了获得 RCE，我们将利用之前发现的任意文件写入漏洞，用多个文件感染日历。当它们组合在一起时，当 macOS Monterey 升级到 Ventura 时，它们将触发 RCE 漏洞。为了获得RCE，我们将利用之前发现的任意文件写入漏洞，用多个文件感染日历。结合起来，当 macOS Monterey 升级到 Ventura 时，它们将触发 RCE 漏洞。  
  
**注入文件#1：   Hacked-$RANDOM.calendar**  
  
此文件包含类似于 “Siri Suggested” -calendar 的日历数据。该文件包含类似于“Siri Suggested”-calendar 的日历数据。  
  
建议的具有 alert-functionality 的重复事件。这将打开其他注入的文件。建议使用警报功能重复事件。这将打开其他注入的文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vZZfNxKcwj6ibcEuSkjdEDrOpI7EKp7td0erYzWmBQnMyzIhke9SgdD6rI1rWiaF3mBqed0bicZfJGGLUxpeGUYbA/640?wx_fmt=png&from=appmsg "")  
  
**文件注入文件#2：CalendarTruthFileMigrationInProgress 文件**  
  
此文件将确保旧日历格式的现有日历将升级并合并到新数据库。  
  
**注入文件#3：CalPoCInit.dmg**  
  
注入文件 #1 中日历事件中嵌入的警报将触发打开文件 ~/Library/Calendars/CalPoCInit.dmg  
  
  
CalPoCInit.dmg 包含对背景图像的引用，该背景图像将指向外部 samba 服务器。该参考是.DS_Store 中的书签。它存储在该图像文件的根目录中。即使 CalPoCInit.dmg 安装处于隔离状态，安装也会在没有隔离标志的情况下进行。  
## 注入文件#4：stage1.url  
  
嵌入在注入文件 #1 中的日历事件的第二个警报将打开文件 ~/Library/Calendars/stage1.url  
  
该文件 stage1.url 包含一个应用程序的 URL，该应用程序位于先前安装的 samba 挂载中，由注入的文件 #3 触发。此 URL 为 file:///Volumes/CalPoCPayload/MyMidiTest.app。  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vZZfNxKcwj6ibcEuSkjdEDrOpI7EKp7tdnf8UvXdJeUSLx0yILQ1S3kaewxicVBhicSX8njBmlandL9rRNUV85ialw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
