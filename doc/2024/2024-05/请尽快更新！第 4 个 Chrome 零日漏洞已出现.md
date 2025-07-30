#  请尽快更新！第 4 个 Chrome 零日漏洞已出现   
 信息安全大事件   2024-05-24 20:25  
  
谷歌周四推出了修复程序，以解决其  
Chrome  
浏览器中的一个高严重性安全漏洞，据称该漏洞已被广泛利用。  
  
该漏洞的  
CVE  
标识符为  
CVE-2024-5274  
，与  
V8 JavaScript  
和  
WebAssembly  
引擎中的类型混淆错误有关。  
2024   
年   
5   
月   
20   
日，谷歌威胁分析小组的   
Clément Lecigne   
和   
Chrome Security   
的   
Brendon Tiszka   
报告了这一消息。  
  
当程序尝试访问类型不兼容的资源时，会出现类型混淆漏洞。它可能会产生严重的后果，因为它允许威胁参与者执行越界内存访问、导致崩溃并执行任意代码。  
  
这一进展标志着谷歌自本月初以来在   
CVE-2024-4671  
、  
CVE-2024-4761   
和   
CVE-2024-4947   
之后修补的第四个零日漏洞。  
  
这家科技巨头没有透露有关该漏洞的更多技术细节，但承认它“知道   
CVE-2024-5274   
的漏洞存在于野外”。目前尚不清楚该缺点是否是   
CVE-2024-4947   
的补丁绕过，这也是   
V8   
中的类型混淆错误。  
  
通过最新的修复程序，谷歌已经解决了自今年年初以来谷歌在   
Chrome   
中总共解决了八个零日问题——  
- CVE-2024-0519 - V8   
中的越界内存访问  
CVE-2024-0519 - V8   
中的越界内存访问  
CVE-2024-0519 - V8  
  
- CVE-2024-2886 - WebCodecs   
中的释放后使用（在  
Pwn2Own 2024   
上演示）  
  
- CVE-2024-2887 - WebAssembly   
中的类型混淆（在  
Pwn2Own 2024   
上演示）  
  
- CVE-2024-3159 - V8   
中的越界内存访问（在  
Pwn2Own 2024   
上演示）  
  
- CVE-2024-4671 -   
视觉对象中的释放后使用  
  
- CVE-2024-4761 - V8   
中的越界写入  
  
- CVE-2024-4947 - V8   
中的类型混淆  
CVE-2024-4947 - V8   
中的类型混淆  
CVE-2024-4947 - V8  
  
建议用户升级到   
Chrome   
版本   
125.0.6422.112/.113  
（适用于   
Windows   
和   
macOS  
）以及   
125.0.6422.112  
（适用于   
Linux  
）以缓解潜在威胁。  
  
还建议基于   
Chromium   
的浏览器（如   
Microsoft Edge  
、  
Brave  
、  
Opera   
和   
Vivaldi  
）的用户在修复程序可用时应用它们。  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__2" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__3" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100005621" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
  
