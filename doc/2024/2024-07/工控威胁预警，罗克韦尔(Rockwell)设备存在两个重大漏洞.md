#  工控威胁预警，罗克韦尔(Rockwell)设备存在两个重大漏洞   
疯狂冰淇淋  FreeBuf   2024-07-06 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
近日，微软在 Rockwell PanelView Plus 设备中发现并披露了两个重大漏洞，未经身份认证的攻击者可远程利用这些漏洞执行远程代码和发起拒绝服务（DoS）攻击。  
  
  
微软的调查结果揭露了在广泛使用这些人机界面（HMI）图形终端的工业领域存在的严重安全漏洞，凸显了在工业自动化系统中采取强有力的安全措施以防止潜在破坏的迫切需要。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icibtibY92B7JPGmVIkxYSgCwg2iaOfZa3scGiakCclOHs0hkbfdmRGc51sWvoz6QhhW2nh2icKuy94MHw/640?wx_fmt=png&from=appmsg "")  
  
  
**RA PanelView Plus 设备漏洞细节**  
  
##   
  
远程代码执行 (RCE) 漏洞被识别为 CVE-2023-2071，CVSS 评分为 9.8，涉及对设备中两个自定义类的利用。攻击者可滥用这些类上传并执行恶意 DLL，从而有效获得设备的远程控制权。  
  
  
DoS 漏洞被识别为 CVE-2023-29464，CVSS 评分为 8.2，利用相同的自定义类发送设备无法处理的伪造缓冲区，导致系统崩溃。  
  
  
**漏洞发现和披露**  
  
##   
  
PanelView Plus 设备在工业自动化领域发挥着至关重要的作用，因此发现的漏洞尤其令人担忧。攻击者利用这些漏洞可以远程执行代码，可能导致运行中断，给受影响的组织造成重大经济损失。  
  
### 漏洞发现  
  
  
Microsoft Defender for IoT 研究团队的主要职责之一是确保对操作技术 (OT) 和物联网 (IoT) 协议进行全面分析。  
  
  
在调查过程中，该团队观察到两个通过通用工业协议 (CIP) 通信的设备之间存在合法的数据包捕获。一个涉及注册表值「ProductCode」路径的可疑远程注册表查询引起了对潜在漏洞的担忧。  
  
  
**协议深度分析**  
  
  
CIP是一种为工业自动化应用设计的面向对象协议。信息针对的是由类 ID 和对象实例 ID 标识的特定对象。该协议包括一个服务代码，表示要在对象上执行的操作。  
  
  
微软的分析显示，观察到的通信涉及特定供应商的服务 ID 和类 ID 值，这促使对 HMI 固件进行进一步调查。  
  
  
**固件分析和利用方法**  
  
  
PanelView Plus HMI 在 Windows 10 IoT（或 Windows CE 上的旧版本）操作系统上运行。微软团队从固件中提取了相关 DLL 和可执行文件，以了解设备如何处理 CIP 请求。  
  
  
他们发现，某些 DLL 管理着负责读取和写入注册表键值的自定义 CIP 类，这一发现导致确定了两个可被利用来远程执行代码的自定义类。  
  
  
第一个自定义类接受 DLL 路径、函数名称和参数，加载 DLL 并执行指定函数。尽管验证功能将函数名称限制为预定义值，但微软还是找到了利用该类的方法。第二个自定义类允许在设备上读写文件，但验证不那么严格，为上传恶意 DLL 提供了途径。  
  
  
微软通过编译与 Windows 10 IoT 兼容的恶意 DLL 演示了一种利用方法。他们使用第二个自定义类来上传 DLL，并将其放置在特定文件夹中。然后，使用第一个自定义类执行名为 remotehelper.dll 的 DLL，使攻击者能够远程控制设备。这一概念验证证实了漏洞的严重性和被利用的可能性。  
  
### 漏洞披露  
  
  
微软安全漏洞研究（MSVR）团队在分析发现这些漏洞后，于 2023 年 5 月和 7 月通过协调漏洞披露（CVD）与 Rockwell Automation 分享了他们的发现。Rockwell Automation  迅速做出响应，于 2023 年 9 月和 10 月发布了公告及安全补丁。  
  
  
**缓解和保护措施**  
  
  
##   
  
为降低与这些漏洞相关的风险，微软建议采取以下措施：  
  
- 应用补丁：确保受影响的设备已更新最新的安全补丁。具体来说，安装补丁 PN1645 和 PN1652 以解决已识别的漏洞。  
  
- 网络隔离：断开 PLC、路由器和 PC 等关键设备与互联网的连接，并确保正确的网络分段。  
  
- 访问控制：限制只有授权组件才能访问 CIP 设备。  
  
- 利用工具：使用 GitHub 上提供的 Microsoft 工具对 Rockwell Rslogix 设备进行扫描和取证调查，以确定受影响的设备并确保其相应的安全。  
  
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
> https://www.hendryadrian.com/cyware-rce-dos-exploits-found-in-rockwell-panelview-plus-patch-now/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494513&idx=1&sn=d121e4f2e20b5ccd61ecf0ad3d8c2106&chksm=ce1f11eef96898f81380d9a50b1420949d8ab4fb9df77944c1d0a9368a1aa2df63106b75b47b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493976&idx=1&sn=70a35df0a9bd52d9ac09818483ff8810&chksm=ce1f13c7f9689ad10260fd6af11bcf78034d697b75e295281d4d5ce4a941d42ec8a24b9fc044&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
