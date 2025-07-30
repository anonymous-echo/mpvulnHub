#  利用 API 和硬件漏洞控制数百万台智能称重机   
原创 T10Ng7_7  山石网科安全技术研究院   2025-04-20 01:02  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**通过一个漏洞，竟然能控制百万台智能体重秤！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在数字化浪潮席卷生活的当下，智能设备的普及带来了前所未有的便利，但同时也引发了新的安全担忧。最近，一篇关于智能体重秤安全漏洞的研究文章引起了极大的关注。作者通过逆向工程和漏洞挖掘，竟然发现了可以控制数百万台智能体重秤的漏洞！这不仅展示了智能设备背后隐藏的安全隐患，也提醒了我们硬件与网络安全结合的重要性。今天，我们希望通过分享这篇文章[1]，从端到端解析联网智能设备的入侵过程，聚焦用户-设备关联这一关键工作流，与大家共同探讨智能设备的安全性问题。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、互联网连接的......体重秤???**  
  
  
某次假期中，作者注意到酒店健身房体重秤屏幕上有个奇怪的WiFi图标。令人震惊的是，人们竟然认为给体重秤联网是个好主意（安息吧），物联网垃圾[2]。在亚马逊搜索后，作者发现大量支持WiFi/蓝牙连接的选项，它们的移动应用代码存在惊人的相似性。  
  
  
![Weighing Machines on Amazon](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRUs3RYKFNuUNQUPpsG3uHs4uKOM2J7sicfcpGY7UQctHRTHibFLdRmpsMyZbmzMKelIpNDkoficzDiaA/640?wx_fmt=png&from=appmsg "")  
  
  
许多产品其实来自同一家OEM厂商。即使不同厂商的代码库略有差异，查看相关Android应用也会发现它们共用  
com.qingniu.heightscale  
等库文件，显然因为从头开发兼容库成本太高。  
  
  
![Qingniu Library on Arboleaf App](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRUs3RYKFNuUNQUPpsG3uHsyzlCcN7F4uqdT1lbn6CHzibQPVqbBZMFia3ibCbzV5mvjFicRPMCn2KE2g/640?wx_fmt=png&from=appmsg "")  
  
图注：Qingniu Library on Arboleaf App  
  
  
![Qingniu Library on Renpho App](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRUs3RYKFNuUNQUPpsG3uHsncwLH6qroCSwV5JwLbOPWz3M4eWtBsUQsTr0I1qpCpicH6Ja3zrgQHA/640?wx_fmt=png&from=appmsg "")  
  
图注：Qingniu Library on Renpho App  
  
  
虽然BLE协议相关代码很有趣（可解析操作码通过蓝牙通信），但  
openScale  
[  
3]  
项目已  
对多数  
协议进行逆向和文档化。近距离物理攻击并非本文重点。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、更深入的了解**  
  
  
要实现大规模入侵，用户-设备关联流程是关键突破口。当用户首次使用智能设备时，通常需要登录移动应用扫描二维码或通过蓝牙配对。完成此流程后，用户账户即与物理设备绑定于厂商的Web服务。  
  
  
这个流程的安全实现颇具挑战。从出厂开始，每个设备都需要唯一的标识符/密钥，避免误绑其他设备。最低安全级别的实现会使用UUID、MAC地址或序列号等静态字符串。虽然这些可作为  
标识符  
，但作为  
认证密钥  
并不安全——即使随机生成难以暴力破解，密钥泄露后也难以撤销。  
  
  
更安全的方案是生成公私钥对。但这仍存在物理内存提取风险，若密钥生成过程存在缺陷，攻击者仍可能伪造任意设备密钥。传统解决方案依赖PKI和证书体系实现便捷的证书吊销。  
  
  
典型流程如下：  
  
1.用户安装移动应用并登录账户  
  
2.通过应用连接硬件设备  
  
3.硬件设备密钥发送至移动应用  
  
4.应用将用户凭证（如会话令牌）和设备密钥发送至服务器  
  
5.服务器验证凭证真实性并绑定账户与设备  
  
6.用户可通过互联网远程控制设备并获取数据  
  
  
看似合理，但隐患何在？  
  
  
**（一）OEM中的SQL注入（绕过BT-WAF）**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
某OEM厂商在起跑线就栽了跟头。无需购买实体设备，作者通过枚举移动应用的API端点发现  
api/ota/update  
接口，希望借此获取固件深入分析。虽然反编译的Java代码能重构JSON请求体参数，但厂商实际提供的更新寥寥无几。  
  
  
在探索API时，作者发现多个端点存在基础SQL注入漏洞。有趣的是，服务器使用了名为"宝塔云WAF（BT-WAF）"的国产防护系统，比常见WAF更难绕过。其中  
/api/device/getDeviceInfo  
端点允许通过序列号查询设备信息——该序列号在此厂商设计中同时作为  
标识符和认证密钥  
，且实际是设备存储的随机生成MAC地址！  
  
  
初始漏洞利用载荷：  
  
```
{  "serialnumber":"'001122334455"}
```  
  
  
经过反复试验，最终构造出绕过BT-WAF的有效载荷：  
  
```
{  "serialnumber":"'or\n@@version\nlimit 1\noffset 123#"}
```  
  
  
分解利用原理（假设原始  
SQL为SELECT * FROM devices WHERE serial = 'INJECTION'  
）：  
  
1.  
@@version  
始终为真，替代  
1=1  
  
2.  
\n  
换行符替代空格分割语句  
  
  
通过递增  
offset  
参数，最终泄露超过20万台设备的认证密钥！  
  
  
**（二）获取Withings WBS06串行调试Shel**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
研究其他设备时，作者注意到Withings Body体重秤（与诺基亚合作款）。该设备支持WiFi/蓝牙连接，应用代码更规范。虽然通过API轻松获取固件，但其ARM裸机固件分析难度极高。  
  
  
通过  
FCC认证  
[4]文档的内部照片确定微控制器型号后，作者在固件中发现疑似Shell的字符串。  
  
```
Connection Manager Shell CommandUsage:  wifi <wifi_sync_flags>            Attempts a Wifi sync with the given flags.            wifi_sync_flags is a combination of the following flags:                0x01 (allow update), 0x02 (store DbLib), 0x04 (send DbLib), 0x08 (send                 rawdata),                0x10 (send wlog), 0x20 (send events), 0x40 (send extras)  wifi_no_update <wifi_sync_flags>            Attempts a Wifi sync, no update allowed (even if set in flags).  wifi_update <wifi_sync_flags>            Attempts a Wifi sync, allows update if available (even if not set in             flags).  bt        Attempts a Bluetooth sync  do   Attempts a Wifi/Cellular sync and fallback to Bluetooth if it fails.
```  
  
  
为什么智能体重秤会内置Shell ？在深入研究过程中，作者发现  
另一位研究人员在Reddit的帖子  
[5]揭示了早期型号WBS05的UART引脚位置。这启发他尝试在WBS06型号上复现该发现。  
  
  
这看起来相当简单，所以作者兴奋地开始尝试在 WBS06 上复制它。最大的线索是 WBS06 底部也有三个相同的孔，分别对应Tx、Rx 和GND UART引脚，将其与 FCC 文档中的内部图片进行比较证实了这一点。  
  
  
![Exterior of WBS06 for UART pins](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRUs3RYKFNuUNQUPpsG3uHsNMUjozyVL2NFz5B6R7YNWLTefHiaBv7O6yfRLQ4KfnReYMrN5an12Iw/640?wx_fmt=png&from=appmsg "")  
  
图注：Exterior of WBS06 for UART pins  
  
  
![Interior of WBS06 for UART pins](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRUs3RYKFNuUNQUPpsG3uHsnkhHlTCJIgxaPHJamKG6N5niczaEgGmQ0AlpibaDichXv5cWQj0bBjzWA/640?wx_fmt=png&from=appmsg "")  
  
图注：Interior of WBS06 for UART pins  
  
  
然而，作者最初的努力失败了。尽管用逻辑分析仪正确地计算出了正确的波特率，但串行连接仍然返回乱码。经过几个小时的痛苦尝试，他意识到问题出在那廉价的CP2102 USB转TTL转换器上，于是换了个更可靠的FT232终于得到了想要的结果。  
  
  
![Logic Analyzer](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRUs3RYKFNuUNQUPpsG3uHsfHZGeHfqncaOsQ7yQtMh1gdiafx8ppPofEEa6ZK8lnGPMUFUVLVibQWw/640?wx_fmt=png&from=appmsg "")  
  
图注：Logic Analyzer  
  
  
现在有了调试shell，就可以探索设备上存储的所有数据，包括证书、密钥等等！当然，虽然这很令人兴奋，但意义不大——作者可以“黑”掉已经拥有的设备，这有什么大不了的。  
  
  
**（三）破坏的用户-设备关联逻辑**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
为真正测试远程攻击向量，需要完整理解设备与API服务器的认证机制及用户-设备绑定流程。  
  
  
以  
connection_manager wifi  
命令为例，该指令会尝试连接API服务器并输出详细调试日志：  
  
```
shell>connection_manager wifi[info][CM] Connection manager request, action = 3, wifi sync flags = 0xffffffff[VAS] t:15[info][CM] Start with cnlib action = 3[VAS] t:15[CNLIB] Recovered LastCnx from DbLib[AM] Defuse id 4[TIME] Current time (timestamp) 0 , 8h 0min 0sec[TIME] Waking up in 16h 90min 60sec[TIME] Add random time 0[AM] Set id 3 at 63060[AM] Set id 1 at 600[CNLIB] Try to connect via wifi (1)[DBLIB][ERASEBANK] Bank 1[info][DBLIB][SUBSADD] 14 0[info][CM] Initializ[VAS] t:15e Wifi[WIFIM] Request[WIFIM] init[VAS] t:15wifi_chip_enablebcm43438_request== Set dcdc_sync ==bcm43438_request: pwron module[WIFIMFW] current_fw == FW_2 1version 1size 80[WIFIMFW] wifi_crc: 0[WIFIMFW] Take current bank[WIFIMFW] Firmware block 1a8000 : OK[WIFIMFW] Wifi Offset 21a370, lenght 58d1d[WWD] HT Clock available in 31 ms[WWD] mac: a4:7e:fa:19:2c:f6supported channels: 13[WIFIM] init OK[info][CM] Wifi initialized[WIFIM] join_configured_ap[VAS] t:15[WIFIM] ssid = ...[WIFIM] key  = ...[WIFIM] WPA key already saved[WWD] join: ssid=<...>, sec=0x00400004, key=<...>[WDM] wwdm_join_event_handler: state=1, wifim_err=9, stopped=0[WDM] wwdm_join_event_handler: state=2, wifim_err=9, stopped=0[WDM] wwdm_join_event_handler: state=2, wifim_err=0, stopped=1[WDM] wwdm_join_event_handler: stopped[WWD] join: wiced_res=0, wifim_res=0[info][WIFIM] join: attempt #0, rc=0[info][WIFIM] join: SSID <...> join rc=0 after 1 attempts[VAS] t:15[VAS] t:15[info][WIFIM] join: RSSI=-64[VAS] t:15[WIFIM] connect: use static ip[WIFIM] Interface UP (Status : 0xf)[WIFIM] netif_up: use DHCP[WIFIM] Interface UP (Status : 0xf)[WIFIM] netif_up:[WIFIM] IP=192.168.0.9[WIFIM] Mask=255.255.255.0[WIFIM] Gw=192.168.0.1[WIFIM] DNS[0]=192.168.0.1[WIFIM] DNS[1]=0.0.0.0[WIFIM] connect_cfg_ap: success[info][CM] Joined configured AP successfully[VAS] t:15[info][CM] Store DbLib...[VAS] t:15[DBLIB][ERASEBANK] Bank 2[info][CM] Store DbLib done[HTT[VAS] t:15S_CLIENT] Init[HTTPS_CLIENT] Init[info][CM] Wslib init successful, carry on[VAS] t:15[WS] WsLib_StartSession[WS] __WsLib_Once[WS] Https_client browsing <https://wbs06-ws.withings.net/once?appliver=1181&appname=WBS06&apppfm=device>[HTTPS_CLIENT] New connection or Adress/Security Changed[HTTPS_CLIENT] Close[HTTPS_CLIENT] Init[HTTPS_CLIENT] Handshake started{"status":0,"body":{"user":[{"userid":...,"screens":[{"id":66,"deactivable_status":6,"src":1,"embid":11,"rk":1}]},...]}}>[DBLIB][ERASEBANK] Bank 1[WS] WSLIB_OK[WS] Https_client browsing <https://wbs06-ws.withings.net/v2/summary?appliver=1181&appname=WBS06&apppfm=device>[HTTPS_CLIENT] Socket already opened[WS] Params <action=getforscale&sessionid=...>{"status":0,"body":[{...}]}>[WS] WSLIB_OK[USLIB] FLUSH STORED MEASURE[USLIB] 0 measure(s) flushed[WS] Https_client browsing <https://wbs06-ws.withings.net/v2/weather?appliver=1181&appname=WBS06&apppfm=device>[HTTPS_CLIENT] Socket already opened[WS] Params <action=getforecast&sessionid=...short=1&enrich=t>...
```  
  
  
尽管如此，多亏了调试日志和从内存中读取各种状态数据，作者终于搞清楚了大部分身份验证流程：  
  
1.设备通过蓝牙从移动应用程序接收WiFi凭证后，现在可以独立连接到API服务器。  
  
2.设备出示其证书并使用双向TLS (mTLS)连接到 API 服务器。  
  
3.API服务器返回一个nonce。  
  
4.设备使用本地私钥对nonce进行签名并将其发送到服务器。  
  
5.API服务器确认签名有效并返回设备会话令牌。  
  
6.设备现在可以使用设备会话令牌作为身份验证与API服务器交互。  
  
  
有趣的是，用户-设备关联工作流程可以通过两种方式完成。第一种方式由用户的移动应用程序发起：  
  
1.移动应用程序已经拥有用户的会话令牌。  
  
2.应用程序通过蓝牙获取设备的会话令牌。  
  
3.应用使用  
Session-Id: USER_SESSION_TOKEN  
向API服务器进行身份验证，并发送请求负载  
userid=USER_ID& sessionidtoken=DEVICE_SESSION_TOKEN  
。  
userid  
是一个简单的递增数字。  
  
4.API 服务器确认  
Session-Id  
和  
sessionidtoken  
均有效，然后将  
userid  
与  
DEVICE_SESSION_TOKEN  
所属的设备ID关联。  
  
  
第二种方式由设备发起：  
  
1.设备已拥有设备会话令牌。  
  
2.设备通过蓝牙从应用获取用户的会话令牌。  
  
3.设备使用  
Session-Id: DEVICE_SESSION_TOKEN  
向API服务器进行身份验证，并发送请求负载  
deviceid=DEVICE_ID& sessionidtoken=USER_SESSION_TOKEN  
。  
deviceid  
是一个简单的递增数字。  
  
4.API服务器确认  
Session-Id  
和  
sessionidtoken  
均有效，然后将  
deviceid  
与  
USER_SESSION_TOKEN  
所属的用户 ID 关联。  
  
  
这两种方法都经过了适当的强化和验证；尝试更改第一个流程中的  
userid  
或第二个流程中的  
deviceid  
都会失败，因为它们与  
Session-Id  
会话令牌不匹配。  
  
  
然而，业务逻辑中存在一个致命缺陷。或许可以用服务器端验证逻辑的近似值来解释这一点：  
  
```
if (req.session.isValid) {if (!validateSession(req.body.sessionidtoken)) {    return error  }const targetSession = fetchSession(req.body.sessionidtoken)// user app-initiated flowif (targetSession.type === 'device') {    associate(req.body.userid, targetSession.id)// device-initiated flow  } else if (targetSession.type === 'user') {    associate(req.body.deviceid, targetSession.id)  }}
```  
  
  
这里有什么错误？好吧，假设一个请求，其中  
Session-Id  
和  
sessionidtoken  
都是攻击者的用户会话令牌，而  
deviceid  
被设置为攻击者不拥有的设备。逻辑仍然会认为这是一个由设备发起的流程，并且永远不会要求攻击者提供与目标  
deviceid  
对应的会话令牌！花几秒钟时间解析代码，记住这一点。  
  
  
相反，代码应该进行额外的验证：  
  
```
if (req.session.isValid) {if (!validateSession(req.body.sessionidtoken)) {    return error  }const targetSession = fetchSession(req.body.sessionidtoken)// user app-initiated flow that validates that user to be associated matches the session token headerif (req.body.userid === req.session.id && targetSession.type === 'device') {    associate(req.body.userid, targetSession.id)// device-initiated flow that validates that devuce to be associated matches the session token header  } else if (req.body.deviceid === req.session.id && targetSession.type === 'user') {    associate(req.body.deviceid, targetSession.id)  }}
```  
  
  
鉴于此错误，根据可用的设备ID，作者估计超过100万个潜在设备可能会重新关联到攻击者的用户账户。  
  
  
即使在假期期间，负责任的披露也迅速修复了漏洞：  
- 2024年12月29日：已报告给供应商  
  
- 2025年1月3日：已确认并修复报告  
  
这表明他们对安全的重视——漏洞会影响每个供应商，但笔者知道自己更愿意从哪个供应商购买。  
  
  
在攻击硬件时，很难从单个设备扩展到完全远程利用（此处双关）。用户设备关联是可以绕过许多标准硬件和网络强化控制的关键流程之一，因为漏洞存在于API服务器上，而不是设备上。尤其对于优先考虑可用性和易于设置的消费级硬件，这一点值得关注。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、相关链接**  
  
  
[1]https://spaceraccoon.dev/pwning-millions-smart-weighing-  
  
machines-api-hardware-hacking/  
  
[2]https://x.com/internetofshit  
  
[3]https://github.com/oliexdev/openScale  
  
[4]https://fcc.report/FCC-ID/XNAWBS06/  
  
[5]https://www.reddit.com/r/withings/comments/18vuckz/comment/kg0rzn3/  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
