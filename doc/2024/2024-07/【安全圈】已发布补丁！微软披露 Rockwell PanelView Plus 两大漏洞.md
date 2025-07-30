#  【安全圈】已发布补丁！微软披露 Rockwell PanelView Plus 两大漏洞   
 安全圈   2024-07-05 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
近日，微软在 Rockwell PanelView Plus 设备中发现并披露了两个重大漏洞，未经身份认证的攻击者可远程利用这些漏洞执行远程代码和发起拒绝服务（DoS）攻击。  
  
微软的调查结果揭露了在广泛使用这些人机界面（HMI）图形终端的工业领域存在的严重安全漏洞，凸显了在工业自动化系统中采取强有力的安全措施以防止潜在破坏的迫切需要。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaZFib8gVe2eDt6IvvzYYsuUIKG8wlFeliaGuOtnnlGTPzaK2dXcO4dw5iaibIMibTic66TxiaLoJgRYx21g/640?wx_fmt=other&from=appmsg "")  
## RA PanelView Plus 设备漏洞细节  
  
远程代码执行 (RCE) 漏洞被识别为 CVE-2023-2071，CVSS 评分为 9.8，涉及对设备中两个自定义类的利用。攻击者可滥用这些类上传并执行恶意 DLL，从而有效获得设备的远程控制权。  
  
DoS 漏洞被识别为 CVE-2023-29464，CVSS 评分为 8.2，利用相同的自定义类发送设备无法处理的伪造缓冲区，导致系统崩溃。  
## 漏洞发现和披露  
  
PanelView Plus 设备在工业自动化领域发挥着至关重要的作用，因此发现的漏洞尤其令人担忧。攻击者利用这些漏洞可以远程执行代码，可能导致运行中断，给受影响的组织造成重大经济损失。  
### 漏洞发现  
  
Microsoft Defender for IoT 研究团队的主要职责之一是确保对操作技术 (OT) 和物联网 (IoT) 协议进行全面分析。  
  
在调查过程中，该团队观察到两个通过通用工业协议 (CIP) 通信的设备之间存在合法的数据包捕获。一个涉及注册表值“ProductCode”路径的可疑远程注册表查询引起了对潜在漏洞的担忧。  
- 协议深度分析  
  
CIP是一种为工业自动化应用设计的面向对象协议。信息针对的是由类 ID 和对象实例 ID 标识的特定对象。该协议包括一个服务代码，表示要在对象上执行的操作。  
  
微软的分析显示，观察到的通信涉及特定供应商的服务 ID 和类 ID 值，这促使对 HMI 固件进行进一步调查。  
- 固件分析和利用方法  
  
PanelView Plus HMI 在 Windows 10 IoT（或 Windows CE 上的旧版本）操作系统上运行。微软团队从固件中提取了相关 DLL 和可执行文件，以了解设备如何处理 CIP 请求。  
  
他们发现，某些 DLL 管理着负责读取和写入注册表键值的自定义 CIP 类，这一发现导致确定了两个可被利用来远程执行代码的自定义类。  
  
第一个自定义类接受 DLL 路径、函数名称和参数，加载 DLL 并执行指定函数。尽管验证功能将函数名称限制为预定义值，但微软还是找到了利用该类的方法。第二个自定义类允许在设备上读写文件，但验证不那么严格，为上传恶意 DLL 提供了途径。  
  
微软通过编译与 Windows 10 IoT 兼容的恶意 DLL 演示了一种利用方法。他们使用第二个自定义类来上传 DLL，并将其放置在特定文件夹中。然后，使用第一个自定义类执行名为 remotehelper.dll 的 DLL，使攻击者能够远程控制设备。这一概念验证证实了漏洞的严重性和被利用的可能性。  
### 漏洞披露  
  
微软安全漏洞研究（MSVR）团队在分析发现这些漏洞后，于 2023 年 5 月和 7 月通过协调漏洞披露（CVD）与 Rockwell Automation 分享了他们的发现。Rockwell Automation  迅速做出响应，于 2023 年 9 月和 10 月发布了公告及安全补丁。  
## 缓解和保护措施  
  
为降低与这些漏洞相关的风险，微软建议采取以下措施：  
- 应用补丁：确保受影响的设备已更新最新的安全补丁。具体来说，安装补丁 PN1645 和 PN1652 以解决已识别的漏洞。  
  
- 网络隔离：断开 PLC、路由器和 PC 等关键设备与互联网的连接，并确保正确的网络分段。  
  
- 访问控制：限制只有授权组件才能访问 CIP 设备。  
  
- 利用工具：使用 GitHub 上提供的 Microsoft 工具对 Rockwell Rslogix 设备进行扫描和取证调查，以确定受影响的设备并确保其相应的安全。  
  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaZFib8gVe2eDt6IvvzYYsuUdaMo0qffQdBfE8WUfkjq1VlUV6WJX6znAADjFouRJHMsDq6qp65z9g/640?wx_fmt=jpeg "")  
[【安全圈】Xbox 全球瘫痪，多个平台用户受影响](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062569&idx=1&sn=739c365bf0e373a1222a899c5045a496&chksm=f36e6f29c419e63f080f1a88dc8fe994e5d82f53c1151b7a186fc6a7a1c1c47121f195248aca&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDLQW996nP0FknIKIIsrFDEpGogw6zzvHQhTiaPsFgYxVYQ3Z6iaYAEibeMes2BqsasBXpLPQnGU5Ng/640?wx_fmt=jpeg "")  
[【安全圈】最高可达 25 万美元！谷歌为 KVM 零日漏洞计划支付巨额奖金](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062569&idx=2&sn=767bae933bd5b26e83854ba266b06a3c&chksm=f36e6f29c419e63f5993bbc04192d54f78a4d8156432a8ed983c7fac21ae9991fcedafb9873c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaZFib8gVe2eDt6IvvzYYsuUSxPoDTho4n6CcNXpDIC7nekTNAdicNWdzETb6BgtSaQxBvynibIeDYsw/640?wx_fmt=jpeg "")  
[【安全圈】Microsoft MSHTML 漏洞被利用来传播 MerkSpy 间谍软件工具](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062569&idx=3&sn=0a96ee46ba5e08d8166d3b3681c3906e&chksm=f36e6f29c419e63f332f4be0908fc8efa13147cbd1317ce06d14a4b823f4cb299f03f95247d4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaZFib8gVe2eDt6IvvzYYsuUw1qMibCXEBEt5nGScGMU08pPUYonwiccnQUIsj0urDLJeXHIL61UB2fw/640?wx_fmt=jpeg "")  
[【安全圈】黑客利用 D-Link DIR-859 路由器严重漏洞窃取密码，必须更换设备避免受害](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062569&idx=4&sn=3c331fa10c28683cf1af086ef876f0d3&chksm=f36e6f29c419e63f1442ca0e55368bc7b55d824604845dd5859497758cc37c289655dcfd39be&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
