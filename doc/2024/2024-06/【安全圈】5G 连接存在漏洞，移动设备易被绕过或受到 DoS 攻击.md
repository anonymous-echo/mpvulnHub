#  【安全圈】5G 连接存在漏洞，移动设备易被绕过或受到 DoS 攻击   
 安全圈   2024-06-29 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
无线服务提供商优先考虑正常运行时间和延迟时间，有时以牺牲安全性为代价，允许攻击者利用这一漏洞窃取数据，甚至更糟。  
  
由于 5G 技术存在漏洞，移动设备面临着数据被肆意窃取和拒绝服务的风险。  
  
在即将于拉斯维加斯举行的「黑帽 2024」大会上，宾夕法尼亚州立大学的一个七人研究小组将介绍黑客如何通过提供互联网连接来窃听互联网流量。这就意味着，间谍活动、网络钓鱼以及更多其他活动都将成为可能。  
  
研究人员表示，这是一种非常容易受到攻击的方式，涉及到通常被忽视的漏洞和几百美元就能在网上买到的设备。  
### 步骤一：设置假基站  
  
当设备首次尝试与移动网络基站连接时，两者要进行身份验证和密钥协议（AKA）。设备发送注册请求，基站回复认证和安全检查请求。  
  
虽然基站会审查手机，但手机不会审查基站，基站的合法性基本上被视为既定事实。  
  
宾夕法尼亚州立大学研究助理赛义德-穆基特-拉希德（Syed Md Mukit Rashid）解释说：”基站每 20 分钟或 40 分钟广播一次’你好’，以此宣传它们在特定区域的存在。但这些广播消息没有经过身份验证，也没有任何安全机制。它们只是明文信息，因此，移动设备根本无法检查它是否来自伪基站。”  
  
建立伪基站并不像看起来那么困难，只需要用树莓派（Raspberry Pi）或者更好的软件定义无线电（SDR）来模拟一个真实的基站。宾夕法尼亚州立大学的另一位研究助理 Kai Tu 指出：”模拟基站需要的工具都可以在网上买到，然后在伪基站上运行一些开源软件（OSS）就可以以假乱真。”昂贵的 SDR 可能要花费数万美元，而能完成任务的廉价 SDR 只需要几百美元。  
  
一个小装置就能诱使你的手机远离一个已建成的商业发射塔，这似乎过于简单了。但是，利用附近的 SDR 进行有针对性的攻击，可以提供比同时为成千上万人提供服务的基站更强的 5G 信号强度。拉希德说：”从本质上讲，设备会尝试连接到最好的基站，即提供最高信号强度的基站。”  
### 步骤二：利用漏洞  
  
与其他安全程序一样，AKA 也可以被利用。例如，在一种流行的移动处理器中集成的 5G 调制解调器中，研究人员发现了一个处理不当的安全头，攻击者可以利用这个安全头完全绕过 AKA 进程。全球最大的两家智能手机公司生产的大部分设备都使用了这种处理器，具体不方便透露是哪两家公司。  
  
在吸引到目标设备后，攻击者可以利用这种 AKA 绕过返回恶意制作的 “接受注册”信息，并启动连接。这样一来，攻击者就成了受害者的互联网服务提供商，能够以未加密的形式看到受害者在网上的一切行为。他们还可以通过发送鱼叉式网络钓鱼短信或将受害者重定向到恶意网站等方式与受害者互动。  
  
虽然 AKA 绕过漏洞已经很严重了，但研究人员还发现了其他漏洞，允许攻击者确定设备的位置，并执行拒绝服务（DoS）。  
### 如何确保 5G 安全  
  
宾夕法尼亚州立大学的研究人员已经向各自的移动供应商报告了他们发现的所有漏洞，这些供应商都已经部署了补丁。  
  
不过，更持久的解决方案必须从确保 5G 身份验证的安全开始。正如拉希德所说：”如果要确保这些广播信息的真实性，就需要使用公钥（基础设施）加密（PKI）。而部署 PKI 的成本很高，需要更新所有的基站。”此外，还有一些非技术方面的挑战，比如谁将是公钥的根证书颁发机构等等……  
  
这种大改不太可能在短期内发生，因为 5G 系统是在知道以上情况的情况下建立的，以纯文本形式传输信息是出于特殊原因。  
> “这是一个激励机制问题。信息是以毫秒为单位发送的，因此如果采用某种加密机制，就会增加基站和用户设备的计算开销。”拉希德解释说，计算开销也与时间有关，因此从性能上来说会慢一些。  
  
  
拉希德表示，性能方面的激励要大于安全方面的激励。但无论是通过假基站、Stingray 设备还是其他手段，攻击者发起攻击都利用了基站的初始广播信息缺乏验证这一特点，这是万恶之源。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhicY8TTBlgZFoOljxwmf23JtA7X7cPrrIIibibG2LCs8qNnibZWQdKc8IGB8tQR44XnU3l7MulwnCP5g/640?wx_fmt=png&from=appmsg "")  
[【安全圈】网安企业360三位员工因窃取他人虚拟币被判，共计获利250余万](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062300&idx=1&sn=082f9d6435963eb17fb6eaae004987a1&chksm=f36e6e1cc419e70a8fe2deef800f8f9fff76dad150771c5884575bad84a00cafb6e46eb195de&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaMLicibeYCg8eQoAmQ39GfIsXMUuDU03xwPTHpic8b1r5wpE0Mz9yJN9ywfM95rRHR6kWQv1ufoRYicg/640?wx_fmt=jpeg "")  
[【安全圈】为阻止种子下载服务，韩国电信巨头KT向60万用户电脑植入恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062300&idx=2&sn=384d65577ea85f9a595237ad50cff008&chksm=f36e6e1cc419e70aeac4c689559357000b708a10dfaf607938de66882bba3f712ff2e2df0491&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgK1DO9pswib04S8RU8ArpaK51KyMJD9ibxBSa8mUBYiaDykQcxeluhCTuRneYqbibic5RDpoVFC2Rrafw/640?wx_fmt=png&from=appmsg "")  
[【安全圈】售价 15 万美元，影响 Linux 内核的 UAF 零日漏洞在暗网出售](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062300&idx=3&sn=5f32791db93bd0f2f45b960437353863&chksm=f36e6e1cc419e70a4a1039e03e8279b7bcbf5fe7e3eee87b8d822834c12b447c62bb5910e5f6&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliamkv1f9zquk5B1GEBYNFHToFsCNG7iaiaqDlP9piavkQOy7twl4k6EdApR6icZBgQ7goxF8mhapAuMiaw/640?wx_fmt=jpeg "")  
[【安全圈】MOVEit 又曝出高危漏洞，又要来一次供应链大事件？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062300&idx=4&sn=eef50c8162b1fe1147e683a139687387&chksm=f36e6e1cc419e70a8f597de78138b1394cd69c24128d6f69e09c6e3d0322ac93d4c4cbd121f0&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
