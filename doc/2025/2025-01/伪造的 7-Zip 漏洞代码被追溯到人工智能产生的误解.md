#  伪造的 7-Zip 漏洞代码被追溯到人工智能产生的误解   
 Ots安全   2025-01-03 06:49  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad8Eh30fibaTM0yN24SRibKIxjYicJIq1fiaXA1N0rSwmUYR4I3LBHAZP1UoBWiaAvk4NpicfsZ32AIj2Mw/640?wx_fmt=jpeg&from=appmsg "")  
  
最近有消息称，流行的开源文件归档软件 7-Zip 存在一个严重的零日漏洞，这一说法遭到了该软件的创建者和其他安全研究人员的质疑。   
- X 上的一名用户 (@NSA_Employee39) 声称发现 7-Zip 的零日漏洞，该漏洞存在严重的缓冲区溢出漏洞。  
  
- 据称，该漏洞涉及一个精心设计的 .7z 档案，其中包含格式错误的 LZMA 流，可执行任意代码。  
  
- 网络安全专家和 7-Zip 的创建者 Igor Pavlov 驳斥了这一说法，称其功能不存在且复制尝试失败。  
  
- 研究人员表示，该漏洞代码可能是由人工智能生成的，因此其可信度较低。  
  
- 该事件凸显了零日漏洞的持续威胁以及强有力的网络安全措施的重要性。  
  
网络安全社区最近面临着一场轰动，起因是社交媒体平台 X（正式名称为 Twitter）上的一名用户声称拥有流行文件归档程序 7-Zip 的零日漏洞。  
  
供您参考，该用户名为 @NSA_Employee39 的用户声称他们发现了一个严重漏洞，该漏洞可能允许攻击者通过利用7-Zip 软件中的缓冲区溢出在受害者的系统上执行任意代码。该用户在 Pastebin 上提供了一个代码片段，据称演示了此漏洞。  
  
“此漏洞利用了 7-Zip 软件的 LZMA 解码器中的漏洞。它使用精心设计的带有畸形 LZMA 流的 .7z 存档来触发 RC_NORM 函数中的缓冲区溢出条件。通过对齐偏移量和有效载荷，该漏洞利用操纵内部缓冲区指针来执行 shellcode，从而导致任意代码执行，”用户在 Pastebin 上写道。  
  
尽管最初引起了关注，但网络安全专家很快开始对该漏洞的有效性表示怀疑。复制该漏洞的尝试失败了，导致人们对该代码的有效性产生了怀疑。  
  
7-Zip 的创始人 Igor Pavlov 后来驳斥了这一说法，他表示，所谓的漏洞依赖于7-Zip LZMA 解码器中不存在的函数（“RC_NORM”） 。Pavlov 认为该代码可能是由 AI 模型生成的，这进一步削弱了其可信度。  
  
此外，安全研究员 @LowLevelTweets 报告称无法重现声称的漏洞，并表示在测试期间没有导致崩溃、挂起或超时。这些发现表明，报告的 7-Zip 零日漏洞可能是误报，可能是由人为生成的代码或对软件内部工作原理的误解引起的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad8Eh30fibaTM0yN24SRibKIxvciaqEXfab3GbPMKXaku1Fj7tueEDXUMyElsSkSEf78qiafVjSEAQUCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
虽然这起事件被证明是一场虚惊，但零日漏洞威胁仍然令人担忧。这些漏洞非常危险，因为软件开发人员不知道它们，因此缺乏任何预先存在的防御措施。  
  
上个月，Hackread报告了一个 Windows 零日漏洞，允许攻击者通过欺骗性方法窃取 NTLM 凭据。该漏洞影响了各种 Windows 系统，包括 Windows Server 2022、Windows 11（最高至 v24H2）、Windows 10（多个版本）、Windows 7 和 Server 2008 R2。  
  
为了防范零日漏洞，全面的安全软件非常重要，因为它可以提供针对各种威胁（包括病毒、恶意软件和零日漏洞）的基本保护。这些解决方案通常包括实时威胁检测、高级威胁防御和强大的隐私功能等功能，以保护用户免受网络安全威胁。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
