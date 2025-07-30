#  APP渗透测试 -- ZipEntry漏洞   
 网络安全者   2025-02-07 16:00  
  
本套课程在线学习（网盘地址，保存即可免费观看）地址：  
  
链接：https://pan.quark.cn/s/eaad210c3229  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczEpyUZZ9H8QUXTYQI7fBMic6BX0NKo66Rs4xEA6vtXzaIgCqLHwhibSne0gBp2iba32xiabbiaicaWgrXA/640?wx_fmt=png&from=appmsg "")  
  
00:00 - APP安全检测及on chip解压缩漏洞解析  
  
对话首先介绍了通过在线工具如360、腾讯等对APK文件进行静态分析的检测方法，以及这些方法可能存在的局限性。随后，讨论了具体的安全问题，包括通过JavaScript接口调用执行恶意代码的风险、SSL通信服务端检测信任证书的不足导致的中间人攻击，以及未验证的跨域数据传输。最后，重点讲解了on chip解压缩过程中的漏洞，即解压时使用get name获取压缩文件名但未进行校验，攻击者可利用此漏洞构造恶意文件，进行目录跳转并覆盖其他文件，从而导致代码执行。  
  
05:38 - 安卓APP中的任意代码执行漏洞解析  
  
讨论了通过覆盖dex文件来实现任意代码执行的原理和方法，特别是在APP采用热更新、动态加载或插件形式时，利用解压缩过程中的路径构造漏洞，可以实现对目标APP的恶意代码注入。通过具体代码示例，详细解析了利用ZipInputStream和ZipEntry类在解压缩过程中的潜在安全风险。  
  
10:04 - 操作系统中特殊字符在文件路径中的限制及攻击原理  
  
对话讨论了在操作系统中，包括Windows和类Unix系统中，文件路径和文件名的命名规则，特别是对特殊字符如斜杠的限制。进一步解释了在文件创建和解压过程中，如何利用特殊字符和路径构造进行潜在的攻击，尤其是在安卓系统中，利用zip输入流和zip输出流类的特性。最后提到了操作系统对文件名和路径的限制，以及如何利用这些限制进行攻击。  
  
16:51 - 讲解关于文件压缩和解压缩的代码实现  
  
讲解者详细介绍了他编写的一个文件压缩和解压缩程序的代码实现，包括布局文件中包含的两个按钮：一个用于压缩，另一个用于解压缩。他深入解释了在MainActivity的Java代码中，如何设置监听器处理按钮点击事件，以及如何在解压缩过程中处理文件路径和读写操作。此外，他还提到了代码中的潜在攻击点以及如何通过拼接文件名来控制输出流的路径，最终展示了实际的文件读写和压缩过程。  
  
24:19 - 安卓插件化技术中的文件名路径穿越漏洞及其防御  
  
对话详细探讨了在安卓插件化技术中利用特定文件名（包含点点斜杠）进行路径穿越的漏洞，展示了如何通过构造特定文件名实现文件的不当解压，从而导致安全问题。讨论还提出了几种防御措施，包括使用HTTPS通信、检测服务器域名与本地域名是否对应、检测文件MD5值以及在解压时检查并处理包含点点斜杠的文件名。通过这些措施，可以有效避免此类路径穿越攻击，保障应用程序的安全。最后，建议学习者多实践、多分析代码以加深理解，并提供了进一步学习和提问的途径。  
  
该内容转载自网络，仅供学习交流，勿作他用，如有侵权请联系删除。  
  
  
  
  
个人微信：ivu123ivu  
  
  
**各 类 学 习 教 程 下 载 合 集**  
  
  
  
  
  
  
  
  
  
https://pan.quark.cn/s/8c91ccb5a474  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuuhdO7GMx4wqK5PQMWgr8pNaudBlYJUYXP6R6LcL0d3UYmPLoiajIXwaibhvlchGibgiaBGwMSwuq58g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczEpyUZZ9H8QUXTYQI7fBMiceSnu4ZRxgq31OoglicejROTbCtic44UrWKmXEerf7qK609TpAs5WQF9w/640?wx_fmt=png&from=appmsg "")  
  
  
