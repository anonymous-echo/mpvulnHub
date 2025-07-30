#  ChatGPT漏洞允许攻击者在共享对话中嵌入恶意SVG与图像文件   
 中科天齐软件安全中心   2025-05-22 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpCYJynbngmnK15X0g1zjBpQ3bscSjltSXib6f0GCH7AHxqD5ymAJXDQA/640?wx_fmt=png&from=appmsg "")  
  
  
点击  
**蓝字**  
  
关注**中****科天齐**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/Jiavz9UrH80k6HR4Q6depGibYPuibsCT0H4mNibUlthR9spzNo2GelcXcoZypCTrFkpJERkSU7ZJZ1cMPVwESOZFjqYJ71FFkJYB/640?wx_fmt=svg&from=appmsg "")  
  
**漏洞详情**  
  
  
研究人员发现ChatGPT存在一个严重安全漏洞(编号CVE-2025-43714)，攻击者可利用该漏洞将恶意SVG(可缩放矢量图形)和图像文件直接嵌入共享对话中，可能导致用户遭受复杂的钓鱼攻击或接触到有害内容。  
  
  
该漏洞影响截至2025年3月30日的所有ChatGPT系统版本。  
  
  
安全专家发现，当用户重新打开或通过公开链接共享对话时，ChatGPT会错误地执行SVG代码，而非将其作为代码块中的文本显示。这种行为实际上在该AI平台中创建了一个存储型跨站脚本(XSS)漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/Jiavz9UrH80k6HR4Q6depGibYPuibsCT0H4mNibUlthR9spzNo2GelcXcoZypCTrFkpJERkSU7ZJZ1cMPVwESOZFjqYJ71FFkJYB/640?wx_fmt=svg&from=appmsg "")  
  
**攻击原理**  
  
  
与JPG或PNG等常规图像格式不同，SVG文件是基于XML的矢量图像，可以包含HTML脚本标签——这是该格式的合法功能，但如果处理不当则十分危险。当这些SVG文件以内联方式而非代码形式呈现时，嵌入的标记会在用户浏览器中执行。  
  
  
研究人员zer0dac指出："ChatGPT系统在2025年3月30日之前版本会内联渲染SVG文档，而非将其作为代码块中的文本显示，这使得攻击者能在大多数现代图形网页浏览器中实施HTML注入。"  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpHsibnfI1QVQFnyW5toSWImXzIOSMhkllIEbOfFGg3vvRC4UjNlRvnew/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/Jiavz9UrH80k6HR4Q6depGibYPuibsCT0H4mNibUlthR9spzNo2GelcXcoZypCTrFkpJERkSU7ZJZ1cMPVwESOZFjqYJ71FFkJYB/640?wx_fmt=svg&from=appmsg "")  
  
**潜在危害**  
  
  
攻击者可精心设计看似合法的SVG代码嵌入欺骗性信息。更令人担忧的是，恶意行为者可能创建包含诱发癫痫的闪烁效果的SVG文件，对光敏性个体造成伤害。  
  
  
其他平台的类似漏洞报告指出："SVG文件可包含嵌入式JavaScript代码，当图像在浏览器中渲染时就会执行。这会产生XSS漏洞，使恶意代码能在其他用户会话上下文中执行。"  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/Jiavz9UrH80k6HR4Q6depGibYPuibsCT0H4mNibUlthR9spzNo2GelcXcoZypCTrFkpJERkSU7ZJZ1cMPVwESOZFjqYJ71FFkJYB/640?wx_fmt=svg&from=appmsg "")  
  
**应对措施**  
  
  
据报道，OpenAI在收到漏洞报告后已采取初步缓解措施，暂时禁用链接共享功能，但彻底修复底层问题的方案仍在开发中。安全专家建议用户谨慎查看来自未知来源的共享ChatGPT对话。  
  
  
该漏洞尤其令人担忧，因为大多数用户对ChatGPT内容存在天然信任，不会预期平台会出现视觉操控或钓鱼尝试。安全研究人员强调："即使没有JavaScript执行能力，视觉和心理操控仍构成滥用行为，特别是当可能影响他人健康或欺骗非技术用户时。"  
  
  
这一发现凸显出，随着AI聊天界面日益融入日常工作流程和通信渠道，防范传统网络漏洞的重要性正与日俱增。  
  
  
参考来源：  
  
ChatGPT Vulnerability Lets Attackers Embed Malicious SVGs & Images in Shared Chats  
  
https://cybersecuritynews.com/chatgpt-vulnerability-malicious-images/  
  
文章来源:Freebuf  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBp7JvIdiapme1icWoe4JJoRhWk9wNkDQtV0PyGdv7974p3760INMOH1pxw/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpqd8VWQuvOmLpWEKicDN5DTLqnEFGibqRKwVAmtSOEYv5QicufA5ZeoNvQ/640?wx_fmt=png&from=appmsg "")  
  
**往期阅读**  
  
****  
[Node.js 高危漏洞警报(CVE-2025-23166)：可导致远程系统崩溃](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496579&idx=1&sn=2b6a6405c0de361cc29cd59b890bd3d0&scene=21#wechat_redirect)  
  
  
  
[基于凭证的网络攻击发生后需采取的七个步骤](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496539&idx=1&sn=cdd15875369845455abe00c5938086fd&scene=21#wechat_redirect)  
  
  
  
[如何真正实现测试左移](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496524&idx=1&sn=b7bb90003f086a5154c3b0393df718bb&scene=21#wechat_redirect)  
  
  
  
[中科天齐团队发现Apache Roller近年来首个高危漏洞，密码修改后会话仍持续有效](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496507&idx=1&sn=4cdf72a4acbd3b6637ff967a88e2d060&scene=21#wechat_redirect)  
  
  
  
[大语言模型权限泛滥：自主性失控带来的安全风险](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496443&idx=1&sn=6495f96159957ab2fb1bef9e9f4918ba&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpCYJynbngmnK15X0g1zjBpQ3bscSjltSXib6f0GCH7AHxqD5ymAJXDQA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpDMAwfDGCticS20PcHvdZAYSgfj4AzcvObv5PicnWZCdTiajLZHS3dpWNQ/640?wx_fmt=png&from=appmsg "")  
  
软件源代码安全缺陷检测平台  
  
  
**软件安全 网络安全的最后一道防线**  
  
中科天齐公司由李炼博士创立  
  
以“中科天齐软件源代码安全缺陷检测平台  
  
（WuKong悟空）”为主打产品  
  
致力打造安全漏洞治理领域新生态的  
  
高新技术企业  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpF8FibkoVvk6V8Licz1wZ214Jy70Zp90JnFVT90IeBrIicSSyqBjYfupqQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpN1kH3TqNsjzwynoQPVaaLN4iaITGLiaOnk1wMrvGL4vVsNkibnLjCTfiaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpF8FibkoVvk6V8Licz1wZ214Jy70Zp90JnFVT90IeBrIicSSyqBjYfupqQ/640?wx_fmt=png&from=appmsg "")  
  
**长按二维码关注我们**  
  
  
**联系方式：400-636-0101**  
  
**网址：**  
**www.woocoom.com**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpQhngCRq35iaCuI1ongHQD87PhYuA2UBxQW95G0cY7po2fcKzkNBqKSA/640?wx_fmt=png&from=appmsg "")  
  
  
点击在看  
  
分享给小伙伴  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xx53Lt2eIAlHOicCYSasia9MMPRWYM6fBpI9d23Re8HSX1FP9RjiaRiaib0ibvGQTKtdoJ46NIBqZNIwNTTukuLibG7qQ/640?wx_fmt=gif&from=appmsg "")  
  
点击  
**阅读原文**  
，获得免费预约地址  
  
