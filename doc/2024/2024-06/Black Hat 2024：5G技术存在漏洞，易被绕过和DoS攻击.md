#  Black Hat 2024：5G技术存在漏洞，易被绕过和DoS攻击   
疯狂冰淇淋  FreeBuf   2024-06-28 18:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib4dqcV4HBY0Tss2ukcGlYfDFm7wicfDjBe2hO26hZSfV0WRkg56DWy7ErXgLIHVlsgx1jLpymLy5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib4dqcV4HBY0Tss2ukcGlYfiaV3vaPHOxSVugqm3dSYamER40mK0sQZnqyichkdUiajXf95rCVf6ticnw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9Jeia3kKz374L8B6T1akwiaWFfnezfLtmD48biaA3tH7f8jC0QgdLXId0DM1mezicboK0CyJDFwJ8oR4s/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9Jeia3kKz374L8B6T1akwiaWFfnezfLtmD48biaA3tH7f8jC0QgdLXId0DM1mezicboK0CyJDFwJ8oR4s/640?wx_fmt=svg&from=appmsg "")  
  
  
> 无线服务提供商优先考虑正常运行时间和延迟时间，有时以牺牲安全性为代价，允许攻击者利用这一漏洞窃取数据，甚至更糟。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ib4dqcV4HBY0Tss2ukcGlYfcM3g9TkIZ5Zo2OjqeZh1J1Xiaib7ALP1QiboNKljcM6pycA0DKyKJqpOw/640?wx_fmt=png&from=appmsg "")  
  
  
由于 5G 技术存在漏洞，移动设备面临着数据被肆意窃取和拒绝服务的风险。  
  
  
在即将于拉斯维加斯举行的「Black Hat 2024」大会上，宾夕法尼亚州立大学的一个七人研究小组将介绍黑客如何通过提供互联网连接来窃听互联网流量。这就意味着，间谍活动、网络钓鱼以及更多其他活动都将成为可能。  
  
  
研究人员表示，这是一种非常容易受到攻击的方式，涉及到通常被忽视的漏洞和几百美元就能在网上买到的设备。  
  
  
**步骤一：设置假基站**  
  
##   
  
当设备首次尝试与移动网络基站连接时，两者要进行身份验证和密钥协议（AKA）。设备发送注册请求，基站回复认证和安全检查请求。  
  
  
虽然基站会审查手机，但手机不会审查基站，基站的合法性基本上被视为既定事实。  
  
  
宾夕法尼亚州立大学研究助理赛义德-穆基特-拉希德（Syed Md Mukit Rashid）解释说：「基站每 20 分钟或 40 分钟广播一次'你好'，以此宣传它们在特定区域的存在。但这些广播消息没有经过身份验证，也没有任何安全机制。它们只是明文信息，因此，移动设备根本无法检查它是否来自伪基站。」  
  
  
建立伪基站并不像看起来那么困难，只需要用树莓派（Raspberry Pi）或者更好的软件定义无线电（SDR）来模拟一个真实的基站。宾夕法尼亚州立大学的另一位研究助理 Kai Tu 指出：「模拟基站需要的设备都可以在网上买到，然后在伪基站上运行一些开源软件（OSS）就可以以假乱真。」昂贵的 SDR 可能要花费数万美元，而能完成任务的廉价 SDR 只需要几百美元。  
  
  
一个小装置就能诱使你的手机远离一个已建成的商业发射塔，这似乎过于简单了。但是，利用附近的 SDR 进行有针对性的攻击，可以提供比同时为成千上万人提供服务的基站更强的 5G 信号强度。拉希德说：「从本质上讲，设备会尝试连接到最好的基站，即提供最高信号强度的基站。」  
  
  
**步骤二：利用漏洞**  
  
  
##   
  
与其他安全程序一样，AKA 也可以被利用。例如，在一种流行的移动处理器中集成的 5G 调制解调器中，研究人员发现了一个处理不当的安全头，攻击者可以利用这个安全头完全绕过 AKA 进程。全球最大的两家智能手机公司生产的大部分设备都使用了这种处理器，具体不方便透露是哪两家公司。  
  
  
在吸引到目标设备后，攻击者可以利用这种 AKA 绕过返回恶意制作「接受注册」信息，并启动连接。这样一来，攻击者就成了受害者的互联网服务提供商，能够以未加密的形式看到受害者在网上的一切行为。他们还可以通过发送鱼叉式网络钓鱼短信或将受害者重定向到恶意网站等方式与受害者互动。  
  
  
虽然 AKA 绕过漏洞已经很严重了，但研究人员还发现了其他漏洞，允许攻击者确定设备的位置，并执行拒绝服务（DoS）。  
  
  
**如何确保 5G 安全**  
  
##   
  
宾夕法尼亚州立大学的研究人员已经向各自的移动供应商报告了他们发现的所有漏洞，这些供应商都已经部署了补丁。  
  
  
不过，更持久的解决方案必须从确保 5G 身份验证的安全开始。正如拉希德所说：如果要确保这些广播信息的真实性，就需要使用公钥（基础设施）加密（PKI）。而部署 PKI 的成本很高，需要更新所有的基站。此外，还有一些非技术方面的挑战，比如谁将是公钥的根证书颁发机构等等……  
  
  
这种大改不太可能在短期内发生，因为 5G 系统是在知道以上情况的情况下建立的，以明文形式传输信息是出于特殊原因。  
  
  
「这是一个激励机制问题。信息是以毫秒为单位发送的，因此如果采用某种加密机制，就会增加基站和用户设备的计算开销。」拉希德解释说，计算开销也与时间有关，因此从性能上来说会慢一些。  
  
  
拉希德表示，也许性能方面的激励要大于安全方面的激励。但无论是通过假基站、Stingray 设备还是其他手段，攻击者发起攻击都利用了基站的初始广播信息缺乏验证这一特点，这是万恶之源。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.darkreading.com/mobile-security/your-phone-s-5g-connection-is-exposed-to-bypass-dos-attacks  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493976&idx=1&sn=70a35df0a9bd52d9ac09818483ff8810&chksm=ce1f13c7f9689ad10260fd6af11bcf78034d697b75e295281d4d5ce4a941d42ec8a24b9fc044&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493939&idx=1&sn=8c3abe1ec23e6fa5dc21cb8e0d1a4993&chksm=ce1f13acf9689aba1da87cd2ce259f8510c502e974681a3dec60d0e6cefed0bd7e3d1cebd4bf&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
