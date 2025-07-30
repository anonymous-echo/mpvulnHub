#  文件传输平台Cleo零日漏洞，Clop团伙声称对数据盗窃攻击负责   
 E安全   2024-12-17 01:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6wOQSS2Vn3hfvXmlxbZkxngsJar11qhQaM9HoYibnKXib0QQrAd7luWib3u8N2PpRmrOxuWJgtS1QaQg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6wOQSS2Vn3hfvXmlxbZkxngmeAFnFVibVsAQXQ76BOic0bYEszItr7NG23RLnS5qP68TLAjiaVwTrVZQ/640?wx_fmt=png&from=appmsg "")  
  
  
**E安全消息，Clop勒索软件团伙已向BleepingComputer证实，他们是最近Cleo数据盗窃攻击的幕后黑手，利用零日漏洞入侵公司网络并窃取数据。**  
  
  
Cleo是管理文件传输平台Cleo Harmony、VLTrader和LexiCom的开发商，企业使用这些平台与商业伙伴安全地交换文件。  
  
  
**上周五（12月13日）CISA 证实，Cleo Harmony、VLTrader 和 LexiCom 文件传输软件中的关键CVE-2024-50623安全漏洞已被勒索软件攻击利用。然而，Cleo从未公开披露他们在10月份试图修复的原始漏洞被利用了。**  
  
  
10 月，Cleo修复了一个跟踪为CVE-2024-50623的漏洞，该漏洞允许不受限制地上传和下载文件，从而导致远程代码执行。  
  
  
然而，网络安全公司Huntress上周发现，原始补丁不完整，威胁行为者正在积极利用绕过进行数据盗窃攻击。  
  
  
在利用此漏洞的同时，威胁行为者上传了一个JAVA后门，允许攻击者窃取数据、执行命令并进一步访问受感染的网络。  
  
  
**Clop声称对Cleo数据盗窃攻击负责**  
  
  
此前人们认为Cleo攻击是由一个名为Termite的新勒索软件团伙进行的。然而Cleo数据盗窃攻击更接近于Clop勒索软件团伙之前进行的攻击。  
  
  
**在周二联系Clop后，勒索软件团伙向BleepingComputer确认，他们就是Huntress发现的Cleo漏洞以及10月份修复的原始CVE-2024-50623漏洞的最近利用者。**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6wOQSS2Vn3hfvXmlxbZkxngL2ggE7CicDibo1QVpLFCuQibyicFxWa8vCPmqpdvW83VJkxRr0YPwqUojg/640?wx_fmt=jpeg&from=appmsg "")  
  
Clop告诉BleepingComputer  
  
  
勒索团伙宣布，他们正在从其数据泄漏服务器中删除与过去攻击相关的数据，并且只会与在Cleo攻击中被入侵的新公司合作。  
  
  
**“尊敬的公司，由于最近的事件（CLEO攻击），所有公司的数据链接都将被禁用，数据将从服务器中永久删除。我们只会与新公司合作。”团伙的 CL0P^_- LEAKS勒索网站上的一条新消息写道。**  
  
  
“新年快乐 © CL0P^_ 所有他们数据泄露网站上的受害者。”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6wOQSS2Vn3hfvXmlxbZkxngPpBjbGYGLevnQthB35fReQqaj2Gplx7QwzicCjSuFK55HBv6oNXUibcA/640?wx_fmt=png&from=appmsg "")  
  
CL0P^_- LEAKS 勒索网站上的消息  
  
资料来源：BleepingComputer  
  
  
BleepingComputer询问Clop攻击何时开始，有多少公司受到影响，以及Clop是否与Termite勒索软件团伙有关联，但没有收到这些问题的回应。  
  
  
BleepingComputer还在周五联系了Cleo，以确认Clop是否是漏洞利用的幕后黑手，但没有收到回应。  
  
  
**针对文件传输平台漏洞利用**  
  
  
**E安全了解，Clop勒索软件团伙，又名TA505，于2019年3月首次出现，当时它使用CryptoMix勒索软件的变体针对企业进行攻击。**  
  
  
像其他勒索软件团伙一样，Clop入侵企业网络，在其系统内横向传播，同时窃取数据和文件。当他们收集了所有有价值的东西后，在网络中部署勒索软件以加密其设备。  
  
  
**自2020年以来，该勒索软件团伙专门针对安全文件传输平台中以前未知的漏洞进行数据盗窃攻击。**  
  
  
2020年12月，Clop利用Accellion FTA安全文件传输平台上的一个零日漏洞，影响了近一百个组织。  
  
  
2021年，该勒索软件团伙利用了SolarWinds Serv-U FTP软件中的一个零日漏洞来窃取数据和入侵网络。  
  
  
2023 年，Clop利用GoAnywhere MFT平台中的零日漏洞，使勒索软件团伙能够再次窃取 100 多家公司的数据。  
  
  
根据Emsisoft的一份报告，他们此类最重大的攻击利用MOVEit Transfer平台中使用零日攻击，这使他们从2773个组织中窃取数据。  
  
  
目前尚不清楚有多少公司受到Cleo数据盗窃攻击的影响，BleepingComputer 也不知道有任何公司确认通过该平台被入侵。  
  
  
**美国国务院的正义奖励计划目前悬赏1000万美元，用于收集将Clop勒索软件攻击与外国政府联系起来的信息。**  
  
  
  
**精彩推荐**  
  
  
印度制药巨头Cipla遭攻击，Akira勒索软件称窃取70GB数据  
2024.12.11  
  
[](https://mp.weixin.qq.com/s?__biz=MzI4MjA1MzkyNA==&mid=2655348181&idx=1&sn=d70935fbe94891c1997f92cfde96d5a8&scene=21#wechat_redirect)  
  
  
利用GitLab漏洞，美国比特币ATM巨头Byte Federal数据泄露  
2024.12.16  
  
[](https://mp.weixin.qq.com/s?__biz=MzI4MjA1MzkyNA==&mid=2655348234&idx=1&sn=e3bdf86725133b7439aeb030e494ef87&scene=21#wechat_redirect)  
  
  
警惕！Patchwork APT以中国科研为目标开展新一轮活动  
  
2024.12.12  
  
[](https://mp.weixin.qq.com/s?__biz=MzI4MjA1MzkyNA==&mid=2655348194&idx=1&sn=120658534a091c5713c3281ee0b209d5&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xuwKC3XZa5PZwOfyW4oy9y2uKJLHcg0LnRAXiaicvdMTgLgKoxoVJZfmQxUensppSZJSmnIbX3dNiaQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xuwKC3XZa5PZwOfyW4oy9ypIV3ItH0hiazjtk1Qe8wQJHLiaMTtfDZD9UnHrctGwbbbx9NLsQibCa0Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xuwKC3XZa5PZwOfyW4oy9ynjicbtVrTnA8w5v2sLoAjkictk1u5uVGJZ9MMouKDLUqsqXRZjkhU84A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
注：本文由E安全编译报道，转载请联系授权并注明来源。  
  
