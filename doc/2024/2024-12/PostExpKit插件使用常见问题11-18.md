#  PostExpKit插件使用常见问题11-18   
 TtTeam   2024-12-28 16:00  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><section style="margin-bottom: 15px;"><span style="font-size: 14px;"><span style="color: rgb(217, 33, 66);"><strong><span leaf="">声明：</span></strong></span><span leaf="">该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。</span></span></section><section><span style="font-size: 14px;"><span leaf="">请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。</span></span></section></td></tr></tbody></table>  
  
**前言**  
  
好久没发原创文章了，今天我们来分享下写PostExpKit插件和  
星球师傅们在使用过程中  
常遇到的另外10个问题，之前也发了一篇可以先去看下：[PostExpKit插件使用常见问题1-10](https://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247512262&idx=1&sn=cde771026b32bc268f3fb94eaa640382&scene=21#wechat_redirect)  
，  
大家在使用过程中有啥其他问题也可以找我反馈交流。  
  
  
**0x11 Defender拦截.NET执行问题**  
  
Win11/2K16+Defender使用execute-assembly  
执行个别恶意.NET利用程序出现报错：[-] Failed to load the assembly w/hr 0x8007000b  
，Defender  
拦截提示为AMSI，这里以GodPotato为例，BadPotato、DCOMPotato等也会被拦，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9LAzNssxnf5Sb7uvvA3C0zleLw2nRnpqkNpPIBgfesMFt4AKVtM1EJA/640?wx_fmt=png&from=appmsg "")  
  
  
**以下图片来自星球@#师傅提供的实战测试截图：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9pic3MlDPWvkyXQXicyvp01hpchTMMhnhVHBAQlmGHibvOlXPbIBE4POmw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9WQucnVR3jicvVJzaXTwwmk0qV2V4DsB9fDQXTshOynda3dgULgSjYPw/640?wx_fmt=png&from=appmsg "")  
  
  
另外也试了下用ineExecute-Assembly  
执行这些被拦截的.NET程序集，虽然没有再拦截，但报了另一个错误CLR Version  
，如下图所示，这不是没给参数的原因，0x08 InlineExecute[.NET]问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9p3tib2icfb3y1LrRqWpRb90RPwLoxunjFAEqRQSmONwgj7uHqhp75ibvg/640?wx_fmt=png&from=appmsg "")  
  
**注：**  
只有Win11/2K16+Defender才会出现以上两种情况，Win10/2K22+Defender测试都没有出现以上拦截和报错问题，如下图所示，实战中大家自行测试下，如果有发现类似问题欢迎反馈交流。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9cLzLX0GACwqX2SprmB20SrMoeQuu1wVCatSVTHhdEw6Kbnib4hPztpw/640?wx_fmt=png&from=appmsg "")  
  
  
**解决办法：**  
  
使用ASP/.NET脚本上线在w3wp.exe  
进程下使用ineExecute-Assembly  
执行.NET程序时经常会遇到CLR  
版本相关报错，出现该问题的原因很多，以下为我遇到过的一些，仅供参考。  
```
1. ineExecute-Assembly没给参数原因；
2. 目标主机上没有安装.NET 2.0环境原因；
3. ASP/.NET脚本上线w3wp.exe进程原因；
4. Win11/2K16+Defender AMSI拦截原因；
```  
  
  
遇到这种情况时可尝试用spawn  
、inject  
重新生成一个会话再执行.NET程序。当然也可能是因为目标主机上没有.NET 2.0，可以尝试使用静默安装方式安装下.NET 2.0，如下图所示。  
```
beacon> spawnto x64 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
beacon> spawn x64
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9cAJL8GPrGXOBDoN36c3e78WKz8YEMFrvxJSYuUaA6Y4WQvPpHuGqdg/640?wx_fmt=png&from=appmsg "")  
  
  
**注：**  
这里我为了方便测试用的脚本上线，实战中遇到Windows Defender时一般是不能使用ASP/.NET脚本上线的，因为内存会查杀（访问500报错），遇到CLR  
版本问题时可参考以上解决办法。  
```
[-] [-] Process refusing to load v2.0.50727 CLR version.  Try running an assembly that requires a differnt CLR version.

[-] [-] Process refusing to get runtime of v2.0.50727 CLR version.  Try running an assembly that requires a differnt CLR version.
```  
  
  
**插件更新：**  
  
最新版PostExpKit插件已更换为.NET4.0/4.6/4.8  
编译的多个Potato  
利用工具，使其能够解决ineExecute-Assembly  
执行.NET土豆出现的CLR  
版本问题，提升了这些利用工具的兼容性，现在支持在多个受影响版本系统中直接使用ineExecute-Assembly  
执行这些.NET土豆进行提权测试，不会再出现CLR  
版本问题（除了Win11/2K16+Defender  
场景）。  
  
  
**绕过思路：**  
  
虽然没能绕过WDF执行.NET土豆提权，这里给大家另外提供几个绕过思路：我们还可以去试下CLFS  
、CVE-2024-26229  
等其他提权exp，之前有几个师傅就成功使用CLFS  
提过几台Win2k16+Defender+Plesk  
虚拟主机，大家遇到类似场景时可以试试，不过得注意落地的exp需自行做免杀。  
  
  
我本地复现测试环境为Win11+Defender  
，所以这里以CVE-2024-26229  
为例演示，使用PostExpKit  
插件CVE-2024-26229  
无需落地，可直接将当前Beacon提升为SYSTEM  
，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9h044ib8d0ick8eV8yOaW5jlFv1pvuBET7icSAWicibk8dtXFfn8dLuXFQDg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x12 MS14-058提权经常掉线问题**  
  
使用提权模块中的MS14-058  
成功得到一个SYSTEM的Beacon，但没一会就掉线了，这是因为我Profile配置文件中spawnto_x64  
进程secinit.exe  
问题，执行完后会自动退出该进程，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9jlNS3uNAcloCVWtyvC3OIdJCib7Mp75nm4YhfI9NKCOibl3OgqFnScTw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9s7QOQcFHc5kHiaEZA6XxYkWHlc6zoWC12lghlibDMjRF14NGOU4lBB1A/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决办法：**  
  
遇到以上问题时可尝试通过这三种方法解决：**1.**  
不加载Profile；**2.**  
将Profile中的spawnto_x64  
改为一个不会退出的进程msiexec.exe  
；**3.**  
使用内置命令spawnto  
或进程注入模块修改，如下图所示。  
```
spawnto x64 C:\Windows\System32\msiexec.exe
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9lLU4kicMCslzR3IAJGaFbFsDdlCjfP7iaoyhjtlE2XuMfOdmnzuymusQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9UgIgKTaryMwVxernhC8Dpk8wtFSO9InURicQXksLsI17L8eb6yUddjQ/640?wx_fmt=png&from=appmsg "")  
  
  
**0x13 drow_listener函数调用为空问题**  
  
@无法  
师傅反馈的一个Bug，当Profile  
配置host_stage  
为false  
时会导致提权模块中大部分功能在选择listener  
时获取的监听列表为空，Windows Stager Payload  
也一样，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9VDKwtUBzv7LCQXkx7UykdrgnBicr3nia677o84HddWsT4NDzzibClI65w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9xBItv0DkhW8ahCa1zusxG97SnbzX9htDV0C4hLtUW6xiao7KPgg4ibfQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决办法：**  
  
可将escalation.cna  
脚本中的drow_listener  
函数全部改成drow_listener_stage  
函数就能正常获取listener  
监听了，部分stager  
shellcode也得改为stageless  
s  
hellcode，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9qNVulJTlc2dibEEGbr8iaczyOiansDaPWxmaDTjFbaAx6lic9z7PyxHwMA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9VRX79DdId3G3UKnxh8ia3kYjf0ntiatbA4VeFA7sg2d7qShGhboWuXaw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**注意事项：**  
  
默认host_stage  
为true  
，可使用drow_listener  
函数获取监听（stager  
+stageless  
），但将host_stage  
设置为false  
时则强制使用stageless  
，所以导致drow_listener  
函数（stager  
）无法获取监听，必须改用drow_listener_stage  
函数（stageless  
）才能获取监听。  
  
- 设置Profile的host_stage为false虽然能提高安全性，避免我们的C2服务器暴露（被扫描泄露Profile），但不排除还有其他Bug...，而且这样就不能用stager，只能用stageless。  
  
- 如果之前插件中有部分用的stagershellcode，我们修改host_stage使用stageless或者改为drow_listener_stage函数也会导致部分stager无法使用，执行某些提权时可能也会无法上线。  
  
**0x14 InlineExecute[.NET]-AMSI参数问题**  
  
**问题描述-1：**  
  
有师傅反馈在Win2k12使用插件中的InlineExecute[.NET]  
、PotatoThread  
进行提权测试时会出现以下报错问题，这可能是因为低版本系统中默认没有Windows Defender，如下图所示。  
```
[*] Tasked beacon to run .NET program: PrintNotifyPotato
[*] Running inlineExecute-Assembly by (@anthemtotheego)
[+] host called home, sent: 35575 bytes
[-] AmsiScanBuffer failed

[-] Patching AMSI failed.  Try running without patching AMSI and using obfuscation
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9Dqyp9ED8ibStU9cVniazqIKec1R6c30UG2IRTrA60cwlC3S219iamTbMA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决办法-1：**  
  
出现以上报错的原因是我们在inlineExecute-Assembly.cna  
中将全局变量$amsi  
和解析参数$_amsi  
都改为1  
启用了，解决方法也很简单，只需要将这两值都改为0  
即可，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9O8mBo48y7icGLym64EKTGZzMfgfIQvoSwVFbnJibrqX5Q9icvz3rkQeTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9QtrmZy241XPpWvTQSS39k1EP0IKfd5vibCla23abJ0a9z0KxBC0yniaw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**问题描述-2：**  
  
另外在Win2k12测试时发现使用插件中的InlineExecute[.NET]  
如果勾选了AMSI  
参数不只是会出现问题1的报错，而且再次执行其他exp在不勾选AMSI  
参数也没有任何执行回显，执行过程中会有一个conhost.exe  
进程，尝试将该进程结束后再次执行，但仍无法解决无回显问题，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9Lo2luow2ahAIcF7r6p12Nzicd22F25vKTCHXO7NUqTjpL93Kho1LFgg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决办法-2：**  
  
我们实战遇到以上场景时只能通过使用spawn  
、inject  
命令或者重新执行一个CobaltStrike木马获取一个新会话后再次使用InlineExecute[.NET]  
执行.NET提权exp进行提权，如下图所示。  
  
**注：**  
重新生成一个新会话通过ProcessExplorer  
观察到.NET提权exp已执行成功，但还是和上边那张图一样没有执行回显，这里我们还需要exit  
终止之前执行exp的会话，然后再次执行即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9PDRQdsibjjukC9ptlWfgURD3icMYDYFH2o191zjlkCEpaibMyQicoCDyicw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x15 InlineExecute[.NET]插件的利用技巧**  
  
实战中如存在某些防护时可能无法使用execute-assembly  
命令执行.NET提权exp进行提权，如火绒6.0内存防护，遇到这种场景时可以尝试使用inlineExecute-Assembly  
执行，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9PeWTXRkqfyPkJepzgb9LEY2M9dKqqDst34YsD2cG0lP3fcB3TKdmyw/640?wx_fmt=png&from=appmsg "")  
  
  
  
我们在测试中发现使用inlineExecute-Assembly  
执行个别.NET提权exp时会在当前线程中保留高权限Token  
，如：EfsPotato、BadPotato等，其他exp自行测试，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9uQnVKiasXbYz9iaJD6QzGdicgbc4nrfIJ4f9piaYArLN4eDibzicIla9ur4A/640?wx_fmt=png&from=appmsg "")  
  
  
  
使用inlineExecute-Assembly  
执行EfsPotato  
或BadPotato  
后可使用getuid  
命令或inlineExecute-Assembly  
执行sharpcmd  
查看当前权限已经为SYSTEM  
，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9ASJnAO0woVqJibFcFNJicHlpcZlfQtnXtPuxoJJzsibZJro6QTBgC8KXw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**注意事项：**  
  
执行EfsPotato  
或BadPotato  
后不能直接使用sharpcmd  
插件执行whoami  
命令，火绒会拦截，无防护时会提示：拒绝访问，后期的利用方式可参考：0x05 线程土豆提权相关问题，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9ImJxbE7wzyIceaIFphBMQatLt72IdUzUqqe7xDIViaxuHt8rtCgspPg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x16 InlineExecute[.NET]更新后问题记录**  
  
**问题描述：**  
  
更新InlineExecute[.NET]  
后虽然解决了《0x11 Defender拦截.NET执行问题》的CLR  
版本问题，但在测试中发现Win10/2K16  
使用SweetPotato  
执行命令时经常会出现掉线的情况（w3wp.exe  
进程会结束），不过在Win2k8/2012  
可正常执行命令（不要加--amsi  
参数），如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9fQlhYCWYhDPhGxBJ1kiaNK2CtLUdlZiaRxpBgu0yxP9xY6UKG4rxNLjA/640?wx_fmt=png&from=appmsg "")  
  
inlineExecute-Assembly - SweetPotato（Win10）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V923oINNtlAagJIpH5y7m5xmttPA0zwYF4aC2PeJpfdsGbytuMj3CxEg/640?wx_fmt=png&from=appmsg "")  
  
inlineExecute-Assembly - SweetPotato（Win2k12）  
  
  
  
还有PrinterNotifyPotato  
、McpManagementPotato  
这两个exp在使用inlineExecute-Assembly  
执行命令时也会出现掉线的情况，execute-assembly  
执行就没问题，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9Kb168Fvs39vYYvRCoIYnlW3CcHnqficATHAEZs4nfmCU7EUwJcibP3TQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
另外还有EfsPotato  
这个exp在部分Win10/Win2k22  
执行多次命令后也会出现掉线的情况，不过在Win2k12/2019  
可正常执行命令（Win2k12  
不要加--amsi  
参数），如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9CtiaEEN7EP2Hywia77xXl6NicofYAHic9nckOb1N1edIP3MkFtXoKbib1GQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**注：**  
之前NET2.0  
编译的EfsPotato  
在Win10/Win2k22  
还会出现报错5：[x] EfsRpcOpenFileRaw failed: 5  
（已修复，NET4.x编译），或者也可以尝试使用线程土豆进行提权。  
```
#for 4.x
csc.exe EfsPotato.cs -nowarn:1691,618
csc /platform:x86 EfsPotato.cs -nowarn:1691,618

#for 2.0/3.5
C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe EfsPotato.cs -nowarn:1691,618
C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe /platform:x86 EfsPotato.cs -nowarn:1691,618
```  
  
  
  
**解决办法：**  
  
我们在实战中使用inlineExecute-Assembly  
执行以上几个exp时如果出现掉线的情况，这时可以尝试将“  
运行.NET参数  
”改为CobaltStrike免杀木马直接执行上线，如下图所示。InlineExecute[.NET]  
中的其他exp暂时还没发现什么问题，大家如果遇到相关问题时可找我反馈！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOd50EXnf00y6I32icChJEKSXbz84ibT2szXjXsk8DaaHNVapdceh53dpPMgewarjW4s0mGyJ8icJC73g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9oSpmshlia89ZG6qUg0yHq9L59fibuWhb527uh2E17aicX5yCicy1HMogFg/640?wx_fmt=png&from=appmsg "")  
  
inlineExecute-Assembly - EfsPotato（Win10）  
  
  
**0x17 [-] Invoke_3 on EntryPoint failed报错**  
  
**问题描述-1：**  
  
我们在Win2k8  
系统中测试时发现哥斯拉的EfsPotato  
可以正常利用，但是使用PostExpKit  
插件中的EfsPotato  
进行提权时就会出现以下报错问题，如下图所示。  
```
[-] Invoke_3 on EntryPoint failed.
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9z7K332vJGIcIadXMpOsnJolY1r7GwGrStP1SjcwaOytUr6NQxuohww/640?wx_fmt=png&from=appmsg "")  
  
  
  
即使使用execute-assembly  
执行.NET2/3.5  
编译的EfsPotato  
也没有利用成功，好像是用的这个exp有点问题，当时没有解决这个利用失败的问题，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9FVKaQTJ5FTFq6fzLYKM9gFvgibpoFTZsXeF0o78OwSINPFZp4AUaHKg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**问题原因-1：**  
  
因为之前为了兼容性将.NET2/3.5  
编译的多个.NET土豆EfsPotato  
改为.NET4  
编译了，而在低版本系统中又没有这个环境，所以在执行时会出现报错，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9WArOZHgiaibsPdYvmicZaaRCFwliaAPqepHjlzakbsguKzia1Oib2zJjkgUA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决办法-1：**  
  
实战中在Win2k8  
系统中如果遇到以上场景及报错问题时我们可以使用PostExpKit  
插件中的EfsPotato  
土豆的shellcode  
选项来进行上线，不会报错，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V92rpBPdQ02ClNpJp3jGU9FvibGaL69Bk84lVLHYeWDOYOcgdunOZuyUA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**问题描述-2：**  
  
我们在测试中发现有个别场景在w3wp.exe  
进程下使用execute-assembly  
执行EfsPotato  
可能会出现以下报错问题，其他.NET的exp可能也会，但我没有都去测试，如下图所示。  
```
[-] Invoke_3 on EntryPoint failed.
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9sYP3RJBIzoVm2Otlic1EW1jDB2Lo0Ujibf8WwCzicH7moTCt9YS99PIGQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**问题原因-2：**  
  
测试过程中发现原来是已经通过其他exp获取到了目标主机的SYSTEM  
最高权限，但是目前也只有当前线程为高权限，使用shell whoami  
和getuid  
命令看下就知道了，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9E5siaiaXw14hvnTqELyMvRdrvFRV6h5yjOmBUYAiahsUoClyNu6wSNsibA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决办法-2：**  
  
遇到以上场景时可以重新执行一个免杀木马，或者执行rev2self  
命令恢复到原始令牌，然后再去执行EfsPotato  
即可，只要不在高权限线程的w3wp.exe  
进程下执行都OK，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9KtsIjYtmFia6iaiaqMocX3WibQIU5C7cv648b5OAmGuuvOCM60QXgkuoQg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x18 DCOMPotato[BOF]执行报错的问题**  
  
**问题描述：**  
  
我们在测试中发现使用脚本上线在w3wp.exe  
进程下执行DCOMPotato[BOF]  
提权时会出现报错：[-] CoInitializeSecurity fail, Error: 0x80010119  
，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V9HQdQ9g5w3vD62Gib3t5yVKrgjdtEm7dXzLGUbgCUBRQw49MnLZjjXDA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决办法：**  
  
使用spawn  
命令或者重新执行一个木马上线得到一个新会话再去执行DCOMPotato[BOF]  
提权即可，只要不是在w3wp.exe  
进程下执行就不会出现上图中的报错，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgEXunATLNwKWjVTTgj7V94gvc5YFK6qqPxGFpoiaWlBBibAjNYqWibmp2vT5vSrJAFjcQZvIkLNmoQ/640?wx_fmt=png&from=appmsg "")  
  
