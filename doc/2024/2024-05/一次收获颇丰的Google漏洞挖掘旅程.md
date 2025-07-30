#  一次收获颇丰的Google漏洞挖掘旅程   
FreddyLu666  FreeBuf   2024-05-03 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
  
本文由安全专家Henry N. Caga于2024年03月23日发表在InfoSecWrite-ups网站，本文记录了Henry N. Caga的一次漏洞挖掘过程，此次漏洞挖掘的成果得到了Google官方认可，拿到了4133.70美元的漏洞奖金，并让他成功进入了Google名人堂。本文旨在跟大家分享一名专业安全研究人员的漏洞挖掘心路历程，仅出于经验分享和教育目的撰写。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNus9rx8cNpXOCicqxiaWdaeL1uahCAcK6UoI7j39Oe0XialxTKCk6yuxQA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**介绍**  
  
  
  
在网络安全领域中，寻找安全漏洞一直都是一项重要的任务。在我近期的一次安全研究过程中，我偶然发现了一个潜伏在Google子域名中的XSS（跨站脚本）漏洞，该漏洞不仅会成为威胁行为者的一个潜在入口点，而且更重要的是，它能够揭示网络安全实践的重要性，哪怕是Google这样的巨头亦是如此。这一个漏洞，使我进入了Google名人堂并获得了丰厚的漏洞奖励。  
  
  
**漏洞发现**  
  
  
  
作为一名网络安全爱好者，我经常会参加一些所谓的「有道德的黑客活动」，也就是处于善意去搜索目标系统中的安全漏洞，并帮助目标系统提升安全性。当时我正在随意浏览各大热门网站的子域名，并无意中发现了一个跟Google相关的不起眼的子域名和链接。  
  
  
这个URL如下：  
```
https://aihub.cloud.google.com/url?q=https://cidadesmineradoras.com.br
```  
  
乍一看，我的直觉就告诉我这里肯定有问题。  
  
  
**漏洞挖掘小Tip #1：**  
永远要相信你的直觉，如果URL看起来有问题，那估计就是有问题！  
  
  
于是乎，我便尝试往这个URL中的q参数输入各种Payload来对其进行测试，但不幸的是，我并没有成功。测试了各种不同Payload无果之后，我便打算尝试我最喜欢的XSS Payload。  
  
  
我使用的Payload如下：  
```
https://aihub.cloud.google.com/url?q=https://cidadesmineradoras.com.br
```  
  
为了让其正常工作，我需要对特殊字符进行URL编码，例如空格和括号等。  
  
  
处理后的URL地址如下：  
```
https://aihub.cloud.google.com/url?q=https://cidadesmineradoras.com.br%22%3E%3CSvG/onload=alert(document.domain)%20id=hncaga%3E
```  
  
当然了，这个地址也是没有用的，因为我之前对这个目标URL的测试中已经使用过这个Payload了。  
  
  
接下来我要做的就是对Payload中所有的字符进行URL编码，看看是否能够绕过目标站点的过滤器。  
  
  
Payload进行URL编码后如下：  
```
https://aihub.cloud.google.com/url?q=%68%6e%63%61%67%61%22%3e%3c%53%76%47%2f%6f%6e%6c%6f%61%64%3d%61%6c%65%72%74%28%64%6f%63%75%6d%65%6e%74%2e%64%6f%6d%61%69%6e%29%20%69%64%3d%68%6e%63%61%67%61%3e
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNRHe7EyicQ9lkPZmpbwqmUVDia9XEQibUJmee68LJyEibx48ceukHmldXyg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
我对编码后的Payload进行了测试后，发现仍然没起作用...  
  
  
当我打算放弃这个URL时，突然脑子里有个东西一闪而过！  
  
  
**漏洞挖掘小Tip #2：**  
永远不要轻言放弃！  
  
  
在进行漏洞挖掘和Payload处理时，可能需要对Payload进行多次编码，而在很多情况下，这种多次编码的操作可能会给你带来意想不到的效果，所以我打算对已经编码过的Payload再次进行URL编码。  
  
  
Payload两次URL编码后如下：  
```
https://aihub.cloud.google.com/url?q=%25%36%38%25%36%65%25%36%33%25%36%31%25%36%37%25%36%31%25%32%32%25%33%65%25%33%63%25%35%33%25%37%36%25%34%37%25%32%66%25%36%66%25%36%65%25%36%63%25%36%66%25%36%31%25%36%34%25%33%64%25%36%31%25%36%63%25%36%35%25%37%32%25%37%34%25%32%38%25%36%34%25%36%66%25%36%33%25%37%35%25%36%64%25%36%35%25%36%65%25%37%34%25%32%65%25%36%34%25%36%66%25%36%64%25%36%31%25%36%39%25%36%65%25%32%39%25%32%30%25%36%39%25%36%34%25%33%64%25%36%38%25%36%65%25%36%33%25%36%31%25%36%37%25%36%31%25%33%65
```  
  
为了记录下整个过程，我还专门录屏了，视频中我使用了BurpSuite来捕捉XSS弹窗的整个过程：https://youtu.be/29hCunQoUS0。  
  
  
接下来，我打算写一份漏洞报告并将其上报给Google安全团队。但是后来，我发现了一个严重的问题，即我的这个XSS Payload有的时候会失效。像我这种「偏执狂」肯定不允许这种事情发生，但我还是选择先上报漏洞。等了几个小时之后Google安全团队也给我回复了一封电子邮件，果然还是这个问题，因为他们无法使用我的这个XSS Payload复现漏洞：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNycBW0pEuQ6Tf6gtX7al6dGiavAg75DUjEq0phT4qhAJAHk22QJSiaeXg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**漏洞挖掘小Tip #3：**  
如果找到了一个漏洞，请一定要针对这个漏洞进行更深入的挖掘！  
  
  
现在，我就需要深入分析一下这个漏洞了。我发现，这个漏洞要进行2-3次尝试后才能够被触发。我写了一个Bash脚本，并使用curl和Payload请求目标URL 5次，看看有多少请求能够反射XSS Payload：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnN6af7YLNVhloaglZX3kpMODg3fu25fJEzG0ZILt6qWPSvCs0rBAaQWA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
在curl请求的5次响应中，有3次包含了Payload，这也表明5次请求能够触发3次漏洞，下图显示的是反射的Payload：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNxVQibM41KJsNryHdyWGlKRjJ4eZGryDnpoWJ3KBAdefKjmt7AkXicWCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
下面是我写的Bash脚本代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNSme4wMy9U6rhD5xYtoibBJ64wjYaNicZYpfDwPDT7jicHoccJH57jT9yw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
但是别着急，还没结束！我当时觉得已经可以把这些发现上报给Google安全团队了，但是仔细想了一下，还是不够稳妥，于是又分析了一下，我发现原来这里还有其他的XSS漏洞！  
  
  
深入分析和调查后，我发现aihub.cloud.google.com下的所有URL，只要添加了q参数，都可以触发XSS漏洞。通过注入「&q=」和两次URL编码的Payload，就可以成功触发XSS漏洞。  
  
  
为了验证我的发现，我重新爬取了aihub的所有URL，并将它们存储到一个名为「valid_aihub_urls.txt」的文本文件中。  
  
  
然后修改我的Bash脚本，并迭代「valid_aihub_urls.txt」中的所有URL地址，并给每个URL发送5次curl请求以查看XSS漏洞触发情况。  
  
  
下面是修改后的Bash脚本：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNM7xdnKp1BDs80eIgS0B3bbGkkVicEogKzEMQBlHsFuhuYh2SuuuDFQg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
下列命令即可运行该脚本：  
```
./google_poc_search_another_q.sh valid_aihub_urls.txt
```  
  
你猜怎么着？文本文件中每一个有效的URL都能够触发XSS。我甚至还尝试去查询了不存在的目录，并在请求中继续添加了q参数，然而仍然能够触发XSS漏洞，简直是神奇！  
  
  
**漏洞报告和解决方案**  
  
  
  
发现了这个漏洞之后，我知道这个漏洞肯定要立即修复。我按照Google的漏洞披露实践准则，并再次将我发现的漏洞上报给了Google安全团队。整个过程中涉及到提交详细的漏洞文档、潜在的影响和漏洞复现步骤，同时我还提交了我写的Bash脚本。  
  
  
最后，终于搞定了！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNshOjofL21A8N6s5EHE4DsM3jicjibFib2unFMW4gzjS5u33qJrkq2PpLA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Google安全团队的处理非常及时，而且也很专业。他们对漏洞进行了检查，并验证了漏洞的真实性，然后将其处理优先级由P2改为了P1，安全等级由S4改成了S1，并对我的努力表示了感谢和认可:  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNKnyw4ABV7IW45DHa6KtvIgZGvW93RRQWbvjExzDoRaG29OyBDlFoGg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
几天之后，Google安全团队也对我的工作给出了奖励：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNFTfMc2Wq9icHOESNWicRWuYRelBm8bMQQXPvCC7jQaO7xF3aQs96nCqA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
漏洞奖金总共为4133.70美元，其中漏洞奖励为3133.70美元，后面又追加了1000.00美元作为额外奖金。  
  
  
我感觉瞬间达到了「人生巅峰」：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNQpx11HBARt99xnastvuyxPKp4oalnaVjVy3wX2phc9WMpdDe5iayW9w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**漏洞挖掘小Tip #4：**  
提交的漏洞报告要尽可能地详实，最好能够提供自动化的工具或脚本帮助复现漏洞，这样你拿到的漏洞奖励才会多！  
  
  
2024年3月15日，Google安全团队通过邮件告诉我，漏洞已成功修复，子域名也提升了安全保护，不过我再次检查这个地址时，发现返回了502错误：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNLsKMVCGUibzYr3SqLBrY5ul4kGjqAapLcz264vZSOhqVuGUl5NjL0fg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
他们表示aihub已经被启用了，从2024年1月起开始使用Vertex AI：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNodeRQf5riaL0eZoRstkxCceV0oq8WgQWdsUpzsSqG3CTDCIEA3Oh3EA/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**漏洞影响**  
  
##   
  
这个漏洞的影响其实还是比较大的，作为Google的子域名，全球用户都会信任这个子域名是安全的，而这样的域名中存在安全漏洞，绝对是非常可怕的。而这个漏洞可能会带来下列安全风险：  
  
  
1、会话劫持：通过执行脚本代码，威胁行为者可以劫持用户会话，获取目标账号未经授权的访问权，并窃取敏感信息；  
  
2、网络钓鱼攻击：通过开发恶意脚本，威胁行为者能够利用存在漏洞的子域名轻松创建网络钓鱼页面，并欺骗用户输入他们的凭证或其他敏感信息；  
  
3、恶意软件分发：威胁行为者可以使用恶意脚本将用户重定向到托管了恶意软件的网站，并在他们不知情的情况下感染目标设备；  
  
4、数据窃取：该漏洞还可以用来窃取Cookie、令牌或其他身份认证数据，从而影响用户的隐私安全；  
  
5、名誉受损：除了技术层面的影响之外，该漏洞还会影响Google的声誉；  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iceicXm9rVWDtpiblKBvrAvnNbEvXukwnKMibdHf0tpqOTxjj53thI2GjwkyjicH3uN92mESndOyRKFJQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**总结**  
  
  
  
Google子域名中的这个漏洞也给我敲响了警钟，这个漏洞再一次强调了强有力的网络安全保护措施是多么的重要，即使是全球网络科技巨头，也会存在这样的安全风险。这些漏洞的影响远远超出了个人用户的范围，而且会影响到数字基础设施的核心部分。  
  
  
我希望通过分享这一经验，能够提高人们对网络安全重要性的认识，并激发集体努力，建设一个更安全的网络世界。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://y0utu.be/29hCunQoUS0  
> https://medium.com/@hncaga/hacking-the-giant-how-i-discovered-googles-vulnerability-and-hall-of-fame-recognition-694a9c18684a  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493362&idx=1&sn=39c9b1c4d709e5ad0babb44995b0e412&chksm=ce1f1c6df968957be704d2843b3f448b252d2a2e1b5271efa486c3e57819849e0e287b04568b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493318&idx=1&sn=02dc5120e00a3d6759be8fcf1b49ec0a&chksm=ce1f1c59f968954fd868b2f8cefa0e8bc5dd703c36dd6db4fc03923be36783a7d4cc791c18b6&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
