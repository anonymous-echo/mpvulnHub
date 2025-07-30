#  Frida Hook（四）- 通用漏洞挖掘实战思路   
原创 比心皮卡丘  暴暴的皮卡丘   2024-06-23 13:48  
  
本文讲述安卓中漏洞挖掘的思路以及frida在挖掘中的用法，会通过一个靶场APP详细介绍抓包流程、APP对SSL、root、Frida的检测绕过方式、不安全存储的风险、隐藏Activity的风险及加密算法hook调用方式等流程，基本覆盖了常规安卓应用挖掘的流程及思路  
  
测试环境  
  
Burp Suite：  
https://portswigger.net/burp  
  
DVBA 后端服务器：  
https://github.com/rewanthtammana/Damn-Vulnerable-Bank/tree/master/BackendServer  
  
Hashcat：  
https://hashcat.net/hashcat/  
  
SQLite 的数据库浏览器：  
https://sqlitebrowser.org/  
  
JADX：  
https://github.com/skylot/jadx  
  
            
  
抓包  
  
  
为了拦截加密的网络流量，安卓模拟器需要信任 Burp Suite 作为证书颁发机构 (CA)。在 Burp Suite 中，导航至   
Proxy > Options Import/export CA certificate > export certificate in DER format   
。在以下屏幕上，选择一个文件夹并将其命名为证书的存储位置。我的文件夹保存为   
burp.cer   
。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrkUGG36PEL6ylkGPjtvoXVa9ibVAz9D1lOqxXZe0BsewWZYNCu3p5vlg/640?wx_fmt=jpeg "")  
  
  
             
  
需要在安卓模拟器中安装证书才能代理流量。可以使用 ADB 将证书推送到 安卓模拟器上的下载文件夹，以便轻松访问。  
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">adb push burp.cer /storage/self/primary/Download</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrVmricG0SYdTlwEmKicasDGyHUCAf6wecicKficWTwhxpQqNsGicxS2QFgBA/640?wx_fmt=png "")  
  
  
接下来，导航至   
设置>安全>加密和凭据>安装证书>CA 证书，然后从   
   
下载   
目录中选择证书 。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrJQicWCic5jcwTF05ImhpQpmomRCjItkaP2t596LnM2tx8DpV2ry03Vxg/640?wx_fmt=jpeg "")  
  
  
需要重启设备才能完全信任证书。要配置 安卓模拟器以将流量发送到代理，请导航至   
“设置”>“网络和 Internet”>“Internet”>“选择 AndroidWifi 旁边的齿轮”>“选择右上角的编辑”>“高级选项”>“手动配置代理”  
  
             
  
当然也可以直接在安卓浏览器中访问访问Burp的端口，然后下载下来证书再进行安装，这里基本上大家也都会  
  
             
  
启动 DVBA 靶场APP，输入 API URL 的 IP 地址和端口，并验证 Burp Suite 代理历史记录中显示的任何请求。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrZ57TlibtVS8gxKunjIeQmKCV7pfgichkdIba4ExdrYQT2K017b8cs2vQ/640?wx_fmt=png "")  
  
  
             
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrXmXibsmZMGDic2liaaLCw2gib4yAlnibMib8FyAxh2T4k75CjDLa9W01ctow/640?wx_fmt=png "")  
  
  
             
  
对于某些 Android 应用程序，证书固定可用于防止未经授权的第三方拦截流量。从高层次上讲，证书固定会告诉应用程序应该信任哪些 SSL 证书以进行通信。任何未明确信任的证书（包括已安装的 CA 证书）都会导致 SSL 协商错误。在这些情况下，可能需要额外的工具和脚本来绕过 SSL 固定。Objection 有一个内置命令，用于尝试绕过常见的固定形式（   
android sslpinning disable   
），但它可能并非在所有情况下都有效。当出现这些情况时，手头上最好有多种工具和技术。  
      
  
  
绕过frida Check  
  
有些程序会对Frida运行进行检测，一旦检测到就会直接关闭掉APP；下面将讲述下如何绕过Frida 检测，其中 Objection 就会内置 Frida 脚本，可用于分析应用程序的各个方面。当启动靶场APP且使用Objection时显而易见的一件事是 DVBA靶场APP 将立即关闭。  
  
objection –gadget “DamnVulnerableBank” explore  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrBHSCWabcgUwsrqRVuVWNQYPnicFh42os5eA7HxRPcFibYTYJTqYVPJYA/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrq31mNibf5iacuTkgBGcZxXP2TBTfcR0h7e35QgeMzbwwKfick5IaH5Atw/640?wx_fmt=png "")  
  
  
使用 Objection，让我们看看可能已加载哪些功能，并尝试找到应用程序关闭的解决方案。使用   
搜索类   
功能，可以查看已加载的类。  
  
android hooking search classes com.app.damnvulnerablebank  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrId0uian3VOZuYwewiax7e6ibOfoR0NUzjhxUYV2P8kKTJp4ulibT3ghxaA/640?wx_fmt=jpeg "")  
  
  
应用程序加载了一个名字有趣的类：  
FridaCheckJNI   
。让我们使用Objection列出该类使用的方法，以识别可能值得深入研究的功能。  
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">android hooking watch class_method com.app.damnvulnerablebank.FridaCheckJNI --dump-return</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
                 
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrsEz8wKlLDmRYL3VFh0ibHdXia7ibiaopZoRk8S6G5hnEMO33ZeEeGpYrJw/640?wx_fmt=jpeg "")  
  
  
             
  
很快可以发现加载了一个函数来检查 Frida 是否正在运行，并且该函数中只有一个方法。继续查看已识别的方法来进一步了解该函数的实现目的。运行以下命令记录对该方法的调用以及返回值，然后尝试重新启动该应用程序。  
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">android hooking watch class_method com.app.damnvulnerablebank.FridaCheckJNI --dump-return</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrtHcz3gvD00s0Mib1YgVY1muEIsmHlX1tWcoWSricc5Dibgp4CdibjUQEuA/640?wx_fmt=jpeg "")  
  
  
             
  
首次启动靶场APP：DVBA 时，将调用   
fridaCheck   
方法并返回 1，这表示 Frida 已启用，并导致应用程序关闭。Objection 支持更改布尔返回值的功能，但由于该方法返回的是整数，因此就无法绕过App的检测。  
  
那么我们就构造 Frida 脚本，可用于hook方法调用并修改将返回的值。由于 Frida 运行时返回值为 1，因此将值切换为 0 应该可以绕过App检测并允许应用程序运行。  
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">Java</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">.perform(function () {                  <br/><span style="mso-spacerun:yes;">    </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//output to make sure the script is running</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">    </span>console.log(&#34;looking for FridaCheckJNI.fridaCheck()&#34;)                  <br/><span style="mso-spacerun:yes;">    </span>                  <br/><span style="mso-spacerun:yes;">    </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//look for FridaCheckJNI</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">const                   <br/><span style="mso-spacerun:yes;">    </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">FridaCheckJNI</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;"> = </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">Java</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">.use(&#39;com.app.damnvulnerablebank.FridaCheckJNI&#39;);                   <br/><span style="mso-spacerun:yes;">    </span>                  <br/><span style="mso-spacerun:yes;">    </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//hook fridaCheck() method </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">    </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">FridaCheckJNI</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">.fridaCheck.implementation = function() {                   <br/><span style="mso-spacerun:yes;">        </span>console.log(&#34;hooking fridaCheck().&#34;)                  <br/><span style="mso-spacerun:yes;">        </span>                  <br/><span style="mso-spacerun:yes;">        </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//call the function to see original output</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>var value = this.fridaCheck.call(this)                   <br/><span style="mso-spacerun:yes;">        </span>                  <br/><span style="mso-spacerun:yes;">        </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//print the original value, then return 0 to bypass the check</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>console.log(&#34;fridaCheck() returned &#34;+value)                  <br/><span style="mso-spacerun:yes;">        </span>console.log(&#34;switching fridaCheck() to 0&#34;)                  <br/><span style="mso-spacerun:yes;">        </span>return 0;                  <br/><span style="mso-spacerun:yes;">    </span>}                  <br/>});</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span>        <o:page></o:page></p></td></tr></tbody></table>  
             
  
脚本可以在 Objection 中使用 运行   
import bypass_fridaCheck.js  
 。在安卓模拟器中，单击 DVBA 图标运行应用程序，它应该会加载welcome页面。回到终端，   
console.log   
语句显示允许应用程序运行的流程的每个步骤。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmraBVFqg2Rbiaf8G6icEdCjia5dYyZhVLZqvZdEwnWWeAYReCO1qDZokBvg/640?wx_fmt=png "")  
  
  
可以看到成功运行起来APP，此时也不会强制关闭  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmr1G7jq7GJj2dnMNd9dfciaP6o8mjsa10xkUlUJcjvZG0wQBo7yUnYw5g/640?wx_fmt=png "")  
  
  
                 
  
通常，Objection还提供一些其他的检测绕过命令，例如  
  
禁用 SSL pinning：  
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">objection –gadget “DamnVulnerableBank” explore –startup-command ‘android sslpinning disable’</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
禁用 root 检测：  
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">objection –gadget “DamnVulnerableBank” explore –startup-command ‘android root disable’</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
             
  
此时，应用程序的所有 API 调用都应通过 Burp Suite 的代理进行路由，现在可以使用 Frida 实时分析应用程序功能的各个部分。浏览所有功能将让我们了解已实现的内容以及攻击者可能想要关注的领域。此外，应检查数据存储是否存在潜在漏洞或可能暴露的敏感信息。  
  
  
本地文件分析  
  
  
与移动应用程序相关的最常见问题之一是不安全的数据存储。在使用移动银行应用程序时，账户通常会与 PII 相关联。如果设备被盗或感染恶意软件，访问这些信息可能会对设备所有者造成不利影响。  
  
使用 Objection，运行 env 命令来识别应用程序的各种数据目录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrdLbJoZAIRpMk1O6R8bP9EdtpTwgQNdAB5UH9fcLloUxAxsSRibQoiaAw/640?wx_fmt=png "")  
  
  
             
  
请注意，   
/data/user/0/com.app.damnvulnerablebank/  
    
似乎是缓存信息和应用文件的公共目录。此外，一些信息缓存在   
/storage/emulated/0/Android/data/com.app.damnvulnerablebank/   
中。接下来我们将压缩这些目录并将其从设备中提取出来以方便离线查看。  
      
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">tar -zcf /sdcard/Download/data.tar.gz /data/user/0/com.app.damnvulnerablebank                  <br/>

                  <br/>tar -zcf /sdcard/Download/storage.tar.gz /storage/emulated/0/Android/data/com.app.damnvulnerablebank/</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrRCV1duuiaxrHia8NN3q92ibzzCTuA3vHQkQuYbrQNfUBfgovjmzveWurA/640?wx_fmt=jpeg "")  
  
  
             
  
使用   
adb pull  
 ，可以将这些文件下载到本地系统进行审查。在提取的目录中，没有太多可识别的纯文本用户数据或 PII。但是，在   
/data/user/0/com.app.damnvulnerablebank/shared_prefs   
中有一个包含 JWT 的 XML 文档。众所周知JWT令牌包含3个不同的部分：标头、有效负载和签名。标头和有效负载使用 base64 编码，通常包含有关用于生成签名的算法的信息、令牌的颁发时间、令牌的过期时间以及有关用户应具有的访问权限的其他详细信息。使用 Burp Suite 的 JSON Web Tokens 扩展，可以解码并查看令牌中包含的信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrx9xvNwhM8MRtM0xa6z8tSKDJepiaukRPJ1XMKR0HcibqVSxehBD9vG1A/640?wx_fmt=png "")  
  
  
             
  
有效负载包含用户名和   
is_admin   
字段。这意味着 API 依赖于用户提供的数据，这些数据可以被操纵以获取对其他用户名或管理员功能的访问权限。由于 JWT 是使用 HS256 签名的，我们需要寻找签名排除漏洞，或者确定签名是否是使用弱密钥生成的。使用 Hashcat，可以使用单词列表来暴力破解密钥值：  
      
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">hashcat -a 0 -m 16500 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRydXN0ZWRzZWMiLCJpc19hZG1pbiI6ZmFsc2UsImlhdCI6MTY3NDE2MTMwN30.lS5Rwrr5YxU5HzJ-9vm5hgUsl8gCoETpvtUjZwocKW8 secrets.txt</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
-a 0  
    
指定将使用的攻击模式：直接字典攻击  
  
-m 16500   
是将要恢复的哈希算法（JWT）。  
  
Secret.txt   
是可以尝试的密码列表（这里密码字典库是从https://github.com/danielmiessler/SecLists/blob/master/Passwords/500-worst-passwords.txt获取）  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrhTIhKpavlZibSENp0bdssZpNFicfYMwCTzAdAQHZxjvuw34NOKuYHALw/640?wx_fmt=jpeg "")  
  
  
经过爆破发现，签名是使用弱密钥生成的。知道密钥后，就可以为 JWT 生成新签名并操纵有效负载中的值。在 Burp Suite 的代理历史记录中，找到使用 JWT 的请求，右键单击它，然后将请求发送到 Repeater。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrR2zwenW77j64zBZNkg7kuGFA7CvK4kAu0X3XN8eNjQdFNWG6gv5tCA/640?wx_fmt=jpeg "")  
  
  
             
  
将Burp Repeater 中的视图从   
pretty   
切换到   
JSON Web Tokens   
。尝试将   
is_admin   
修改为   
true   
，将   
用户名   
修改为   
admin   
。在屏幕的右侧，选择   
重新计算签名的   
选项，并将密钥输入到下面的输入框中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrRCw6BdFOuUk0NYR01BqYxQQDziaJx5CmOCyicUx1IYE9IHzRpKdyGtPA/640?wx_fmt=jpeg "")  
  
      
  
             
  
服务器接受了 JWT 并提供   
200 OK响应，表明它接受了修改后的 JWT。现在使用修改后的 JWT 覆盖   
   
jwt.xml   
中的值， 看看它是否可以用于访问应用程序内的其他活动。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrKaQ5icaDHlyxxV2JCnMibfwbUOh8FGrhVAFNub9n8XXEdNicJ11mdMs4Q/640?wx_fmt=jpeg "")  
  
  
该文件用于记录用户是否已登录应用程序并缓存帐户详细信息。关闭应用程序并将修改后的 jwt.xml 推送到 Android 设备。下次启动应用程序时，管理员帐户将登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrKsqrea4snbXmjP7fKibpEsPgyEy7x3yUeaQtuUUnTDWVX7h2dDctjyg/640?wx_fmt=jpeg "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrsTzxpoP2icrPhXZbdEOicxvdwkvr3MA3f7jBk2LYYPVjW6bmjCnibdDdg/640?wx_fmt=png "")  
  
  
             
  
可以看到我们已经找到了 靶场APP 中的第一个漏洞！继续进行本地文件分析，让我们回到从设备中提取的目录并尝试识别其他可利用的信息。SQLite 数据库通常用于移动应用程序，因为它们非常适合移动设备的处理限制。通常，这些数据库未加密，因为大多数用户永远不会看到文件的内容。接下来可以使用命令行来搜索sqlite数据库，  
      
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">find . \( -name \*.db -o -name \*.sqlite \-o -name \*.sqlite3 \) -print                  <br/>find . -type f -exec file &#39;{}&#39; \; | grep &#39;SQLite 3.x database&#39;</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmr5wfExjBxsPNF6f3YsfPnicaGe5yU41PVmJCGib204kW1bCFbcGriaNUTg/640?wx_fmt=jpeg "")  
  
  
             
  
搜索文件扩展名没有结果，但搜索文件中的字符串发现了两个需要检查的数据库文件。使用 DB Browser for SQLite，可以打开每个文件并检查其中是否包含未加密且可能用于恶意目的的内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrjxdzyibjEoEFlUkLULV9J6JzibyUu1iaOjFFibLtbGwdUib3NgcqYCjSicpA/640?wx_fmt=jpeg "")  
  
  
             
  
查看 Web 数据文件后发现，有几个数据库表可能值得关注，包括：  
credit_cards、unmasked_credit_cards、payments_customer_data   
等。快速查看每个表后发现，数据库中当前没有数据。这是测试期间需要注意的一点，因为可能存在填充信息的特定功能。  
  
Exploiting Activity  
  
  
查看应用程序用户界面中的活动仅显示可执行的5种不同Activity。使用 Objection 列出Activity可显示更多可用功能。这是因为在构建应用程序时，每个Activity都需要在   
AndroidManifest.xml   
中列出。Objection 从此清单文件中获取Activity列表。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrHXEZ5KKqHiaiawiccicWZo0iceNaiaareFQRCicOBSwluDlWoicgaicCUDqzUJQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrEcCWZQb97icG8ibJB7yo1piaRzZYA3iaO2kUKLaYb06DB97ZxiaqV1Zib0Ig/640?wx_fmt=png "")  
  
  
值得注意的是，某些Activity（例如调试功能）可能被开发人员故意隐藏，或者在构建时被禁用。例如，从屏幕左下角滑动到右上角以访问包含应用程序日志的页面。虽然这些Activity不打算供普通用户使用，但它们通常留在代码中。此外，在未经身份验证的情况下启动活动可能会导致应用程序内出现意外行为。可以使用 Objection 启动列出的Activity  
      
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">android intent launch_activity<activity name="name"></activity></span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrFKt2gwWNnicNs7QVHvbuKsUDl3PSbXD7UaGpN6KRdv8L98gtsXWPR8A/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmriaQxLM4Bhjgx8rpR5NAtmIvyx6iaxMBF5Sf2KpUnnVr4aV1vuIppn0Xw/640?wx_fmt=png "")  
  
  
                 
  
 汇款功能要求先将用户添加为帐户的受益人，然后才能转账。让我们尝试将钱转到我们之前创建的帐户。此攻击的流程如下：  
1. 将用户账户添加到管理员受益人  
  
1. 批准受益人  
  
1. 使用“发送资金”从管理员帐户转账  
  
由于我们可以访问管理员帐户(得益于上一节发现的  
jwt.xml   
漏洞)，可以使用   
添加受益人 Activity  
来添加用户创建的帐户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmreiaC95fenBgHdb1H9X1Uxk2cELelshicborsBYsDmKyZPww9u7LfDhiaA/640?wx_fmt=png "")  
  
  
             
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrd5h2VQHgjOnbPM4LdYFQ8RO0X8EUp5Y2NOeaPb7xn2MIAqnvZO4dEg/640?wx_fmt=png "")  
  
  
             
  
添加帐户后，需要管理员批准。继续使用Objection启动   
“待处理受益人” Activity   
并选择待处理的请求。屏幕上的提示将要求再次输入 ID，该 ID 显示在屏幕顶部  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrvib1RmDcYIcibMicI0BEGtHTMkYIZafrMWmvrqqSRF8lRJkDsFopFDDew/640?wx_fmt=png "")  
  
  
一旦获得批准，重新启动   
查看受益人 Activity  
将显示我们的用户帐户是已批准的受益人。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmriajaJIp6dKB17oIibAGalIadrXkF5K76tD4CrPgUnnRagzrT1aiaMib5wA/640?wx_fmt=jpeg "")  
  
  
使用 Objection 启动   
“发送资金” Activity  
。指定要转账的账号和金额。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrXCyy4k2Zu4wfQtt8eoeOicMw3J7AGGxuIMicahA2FEk5vo3yN1uMa0YQ/640?wx_fmt=png "")  
  
  
 如果成功，查看trustedsec 用户的余额 现在应该会显示额外的100美元。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrKhR2ictHwduh6e3XK96kYnZUz4IBiav9w3kAJgSokDZWib6kgMuXpcnVQ/640?wx_fmt=png "")  
  
  
             
  
通过将身份验证绕过与在 Objection 中启动活动的功能相结合，可以发起对财务造成影响的多步骤攻击。  
  
逆向算法  
  
  
在很多时候，我们就发现App发起请求的时候也会对数据加密或者加签名，此时通常需要对代码进行逆向获取到加解密算法，从而发起伪造合理的请求，接下来仍以靶场APP为例，详细讲解安卓应用算法逆向过程  
  
             
  
到目前为止，在介绍靶场APP应用程序的功能时，每个 API 请求都已记录在 Burp Suite 的代理历史记录中。查看这些请求时，很明显请求和响应中的数据已加密。更具体地说，数据已加密并进行了 base64 编码。如果数据可以解密、修改和重新加密，则可能会允许对 API 进行其他攻击。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrBPlSfC1OGPE85icP5ULHXQ5bK8gFicic23aIeVk0HCddVTAKzsiakcicNsg/640?wx_fmt=jpeg "")  
  
  
为了实现这一点，了解 Android 应用程序的文件结构可能会有所帮助。可以通过将文件扩展名更改为 .zip 来解压 APK 文件，这样就可以提取内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmr3qDd6vmbuYSeljOiaCwYV5KD7X1x6aIKA6dQezIicthOxztwAcFXay9g/640?wx_fmt=jpeg "")  
  
  
此文件夹结构中有一个   
classes.dex   
文件。这是一个包含已编译 Java 代码的可执行文件（Dalvik 可执行字节码）。可以使用   
dex2jar   
之类的工具将 DEX 文件转换为 Java 类文件。可以进一步将 Java 类文件反编译为源代码以便于解释。如果在构建应用程序时未使用代码混淆，则此过程可以让我们更深入地了解应用程序和已引入的漏洞。有许多不同的工具可以为我们进行反编译，但本文将使用的工具是   
JADX   
。安装后，可以运行 JADX-GUI 以提供用于加载 APK 和查看反编译源代码的图形界面。在用户界面中，导航至   
文件 > 打开   
并选择   
dvba.apk   
。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmr2evISNylDYWfVssC6KoWsUao5fGx9rWb4mCCMbPtPCJZwsNA9n4RqQ/640?wx_fmt=png "")  
  
  
展开源代码、app.damnvulnerablebank 文件夹时，您会注意到许多文件名与与移动设备交互时看到的活动相匹配。这些是每个活动的类文件。由于  
Send Money  
 activity在请求和响应中都有加密数据，因此让我们打开该代码进行仔细查看。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrKlnQFZfBsGYfNcKlxNfDyFGjzjESdohibXuRbPBRgV9LO3icDjnaIvnQ/640?wx_fmt=jpeg "")  
  
  
在Burp代理历史记录中，我们在请求和响应中都观察到了属性   
enc_data   
。此时值得注意的是，名称已实现混淆，将类和方法名称更改为无意义的字符串，这会使代码难以阅读和理解。在源代码中，   
enc_data   
根据类   
e   
和方法   
b   
被分配一个值。方法   
b   
被发送一个包含  
to_account   
和   
amount的字符串。  
在类文件的最顶部，我们可以看到类 e 是从包  
  cba 加载的。让我们打开这个类看看代码在做什么。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrnSAFTjFbIghqnbxJmrJd8rRGQhianGjvKMpjbSKN3YuWlUvicmZJWDRw/640?wx_fmt=jpeg "")  
  
  
审计代码后发现，函数   
a   
用于解码和解密数据。函数   
b   
用于在数据加密后对其进行 base64 编码。函数   
c   
用于加密和解密数据。与其尝试重新编码这些函数并将数据复制/粘贴到我们自己的脚本中，不如另外编写一个 Frida 脚本来利用现有函数更快捷  
<table><tbody><tr><td width="552" valign="top" style="width:414.0pt;background:#F5F6F7;border-top:solid #DEE0E3 1.0pt;mso-border-top-alt:solid #DEE0E3 0.25pt;border-left:solid #DEE0E3 1.0pt;mso-border-left-alt:solid #DEE0E3 0.25pt;border-bottom:solid #DEE0E3 1.0pt;mso-border-bottom-alt:solid #DEE0E3 0.25pt;border-right:solid #DEE0E3 1.0pt;mso-border-right-alt:solid #DEE0E3 0.25pt;padding:3.0pt 6.0pt 1.5pt 6.0pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;">Shell                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;"><span style="mso-spacerun:yes;">  </span>setTimeout(function(){                  <br/><span style="mso-spacerun:yes;">    </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">Java</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">.perform(function() {                  <br/><span style="mso-spacerun:yes;">        </span>var crypt = </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">Java</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">.use(&#34;c.b.a.e&#34;); </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//look for class c.b.a.e</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>crypt.a.implementation = function(enc_data){ </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//hook method a</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>console.log(&#34;Encrypted Data:&#34;+enc_data) </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//print encrypted</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">var                   <br/><span style="mso-spacerun:yes;">        </span>value = this.a(enc_data) </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//run the function</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>console.log(&#34;Response Data: &#34;+value) </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//print the plain-text</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">return value;                  <br/><span style="mso-spacerun:yes;">        </span>}                  <br/><span style="mso-spacerun:yes;">    </span>})                  <br/>},10); </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//wait 10ms then run</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//Used when request data is encrypted</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/>setTimeout(function(){                  <br/><span style="mso-spacerun:yes;">    </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">Java</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">.perform(function() {                  <br/><span style="mso-spacerun:yes;">        </span>var crypt = </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;text-underline:single;text-decoration:underline;">Java</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">.use(&#34;c.b.a.e&#34;); </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//look for class c.b.a.e</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>crypt.b.implementation = function(enc_data) {<span style="mso-spacerun:yes;">  </span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//hook method b</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>console.log(&#34;Request Data: &#34;+enc_data) </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//print plain-text</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>let value = this.b(enc_data); </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//run the function</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">                  <br/><span style="mso-spacerun:yes;">        </span>console.log(&#34;Encrypted data: &#34;+value) </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//print encrypted data</span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;">return value;                  <br/><span style="mso-spacerun:yes;">        </span>}                   <br/><span style="mso-spacerun:yes;">    </span>})                  <br/>},10); </span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;font-style:italic;">//wait 10ms then run</span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
一旦导入新脚本并进行传输，Objection 将输出请求数据和响应数据。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLXU3lXN2A8icWgknV2CTVicmrVPaE0Qj2LxqibLHTiaEDvnzbYo1k9pmzNFoBMjIdvia5Orby5H2TuY7og/640?wx_fmt=jpeg "")  
  
  
通过这种方式就可以实现使用未加密的数据来进行漏洞挖掘例如 SQLi。在能够访问所有功能、系统文件和正在传输的数据的情况下，就可以花些时间查找应用程序中的其他漏洞。  
      
  
  
  
  
  
  
