#  黑客眼中的NFC：Mifare安全漏洞大揭秘   
原创 T10Ng7_7  山石网科安全技术研究院   2025-05-19 08:46  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**你以为手中的门禁卡安全无虞？黑客告诉你，Mifare系统的漏洞可能让你的隐私和安全暴露无遗！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
如今，NFC（近场通信）技术已经广泛应用于我们的生活，从门禁卡到公共交通卡，再到各种会员卡，Mifare作为其中的重要品牌，被广泛认为是安全可靠的解决方案。然而，黑客们却发现了隐藏在背后的诸多漏洞[1]。今天，我们就来揭开Mifare的神秘面纱，看看那些看似安全的卡片，究竟存在哪些安全隐患，以及我们该如何应对。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、背景**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d2s8d7QIicqicOBDTcaQhFlnJdTl5iawsd8Qj1dCmiaXMrUSROOSabLzhkZQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
在  
某些时候，简单的标识符已无法确保适当的访问控制，因此消费者转而采用更先进的解决方案：Mifare。但是，基于Mifare的设备是否真的像制造商声称的那样安全呢？让我们一探究竟！  
  
  
Mifare是恩智浦半导体公司旗下的一个非接触式识别器品牌。这种卡使用ISO 14443 A 类标准，工作频率为13.56MHz。  
  
  
银行卡使用的EMV协议也是基于 ISO 14443 A类标准。  
  
  
Mifare技术发明于1994年。1996年，它被集成到首尔公交系统中，随着时间的推移，为满足更高的安全标准，其已成为替代EM410X的核心组件。  
  
  
Mifare识别器通常用于PACS、公共交通系统和各种忠诚度计划。  
  
  
目前，Mifare系列包括以下标识符。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRaga1Vtu9GLhz76NWd7FV4xtnK7L3CsEQEcNibUmv3yJcz5P63qn6HcvVRGHibE0xN4ODWvw8TP90Q/640?wx_fmt=png&from=appmsg "")  
  
  
大多数基于Mifare的物理门禁控制系统都使用Mifare Classic 1K（1K字节内存；4字节UID）；因此，笔者对其进行了更详细的研究。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、数据结构**  
  
****  
  
****  
Mifare Classic 1K的内存组织如下所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d2RM1e3D8umgEob5RnSd63EacZjFvbSbHbBZiaOEyQJortEdicfJAjffXA/640?wx_fmt=png&from=appmsg "")  
  
  
空扇区是最重要的扇区，因为它的第一个块（无论是在扇区中还是在整个标识符中）包含了有关UID和制造商的信息。  
  
  
第二个最重要的部分是Access bits（4个字节）：它们定义了可以使用Key A 和Key B（各6个字节）执行的一系列操作，包括：  
- 读取区块  
  
- 写入区块  
  
- 增加或减少区块值  
  
有时，Key B可能有一些“奇怪”的值，无法用于上述操作。这是因为Key B是可选的，可以用来存储任意数据。  
  
**‘魔法’卡片**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
正如PACS from a hacker’s perspective. Attacks on RFID-based physical access control systems[2]一文所讨论的那样，携带笔记本电脑和Proxmark3进入安全设施并不是一个好主意因为需要隐蔽的攻击方法。理想的解决方案是制作一张与目标公司使用的卡片相似的卡片。  
  
  
你可能会感到惊讶，但这种识别器确实存在！它们被称为“魔术卡”或“中国后门”（第二个名称清楚地表明了它们的来源）。它们与“普通”标识符的主要区别是，所有扇区都可以写入，包括存储UID的扇区。顺便说一句，有一个好处就是这种卡的价格与不可擦写的“同类产品”相差不大。  
  
  
不过，这种“魔术”并非适用于所有Mifare标识符。例如，为MifareClassic 1K找一张4字节UID的“魔术”卡并不难，但为同一张卡找一张7字节UID的中文类似卡就困难得多。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、对Mifare的攻击**  
  
坏消息是某些类型的Mifare标识符几乎不可能被黑客攻击，目前还没有针对EM410X的大规模攻击。但好消息是Mifare仍然可以被黑客攻击，而且某些攻击仍然有效！  
  
**（一）UID仿真和暴力破解**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
有趣的是，有些PACS仅使用所有基于ISO 14443 Type A的系统通用的7字节 UID进行识别。在这种情况下，系统操作与EM410X类似，您可以基于有效 UID生成的标识符尝试枚举。  
  
  
获取有效的UID非常简单：可以使用  
Proxmark3（hf搜索命令）  
等工具轻松提取。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d2icuwG4D4ERe5UOic4AX8QiaHent0sC39sCO0QhEBy2PYdZjiapiaeicOBpQA/640?wx_fmt=png&from=appmsg "")  
  
  
**（二）强制密钥和标准密钥**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
客户从制造商处收到的识别器通常使用标准密钥，以确保能方便地集成到系统中。有时，由于侥幸心理或配置系统的安全人员的疏忽，这些密钥会保持不变。应首先使用这类密钥。  
  
  
为此，请使用以下Proxmark3命令：hf mf chk（传统模式）  
或hf mf fchk  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d28XicEWokKlK3blaoBu0IfYurbCwuPEkPTvuvG8F0Ju41sqBUcickueGQ/640?wx_fmt=png&from=appmsg "")  
  
  
如果无法匹配密钥，可以执行  
hf mf chk -f <dictionary.dic>  
命令，使用自定义字典（如Mifare Default Keys[3])默认密钥）进行流行的攻击。  
  
  
顺便说一句，密钥暴力破解是迄今为止Flipper Zero官方唯一支持的攻击。这就是为什么要花很长时间才能获得完整的标识符，有时甚至根本不可能。  
  
  
如果视角不仅仅是局限于UID呢？你可以完全复制Mifare 1K，因为这类标识符使用的Crypto1加密算法是可以破解的。  
  
  
**（三）Crypto1**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
从未听说过Crypto1？这并不奇怪。这种流密码是恩智浦半导体公司专门为 Mifare开发的，从一开始就用于这些标识符。它的算法通过硬件实现，并嵌入到每个使用它的标签中。  
  
  
Crypto1的工作原理是  
“  
通过隐蔽实现安全”，因此能确保令人满意的安全级别。但在2008-2009年期间，独立研究人员对其进行了剖析，轻描淡写地将其安全性评定为“近乎零”。这项研究使得开发几种有效的攻击成为可能（将在下文讨论）。  
  
  
**（四）Nested攻击**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
这种攻击利用了Crypto1算法中使用的PRNG（伪随机数生成器）的一个固有漏洞。  
  
  
检查标签时，  
“  
Prng检测”字段的值会显示标识符是否易受此类攻击（在下面的截图中，标识符被认为是容易遭受攻击的对象）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d2wX5beFtU5D3aWfcdolKwNArVSC9lxvRh1s1Goy3PRiczEBzpZo88afw/640?wx_fmt=png&from=appmsg "")  
  
  
这种攻击的一大优点是可以离线发送（即只需要一个有效的标识符）。它唯一的缺点是，你必须至少知道一个密钥。  
  
  
那么，漏洞是什么呢？简而言之，伪随机数是根据线性反馈移位寄存器（LFSR）生成的，如果你知道其中一个密钥，就能找出随机值的迭代次数。  
  
  
要发动这种攻击，请使用命令  
hf mf nested --1k -blk <block number> <-a/-b> -k <key>  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d2JUgPicVC89rStpaP2rnJdsAXSmIEVvwWRkibDjPsjlQPpwOVzVoov57A/640?wx_fmt=png&from=appmsg "")  
  
  
**（五）Hardnested攻击**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
如果  
“  
Prng”检测字段的值为  
hard  
，则应使用Hardnested攻击。  
  
  
这种攻击与nested攻击几乎完全相同：它也需要任何扇区中的一个已知密钥和一个有效标识符。  
  
  
发动Hardnested攻击可以使用以下指令：  
hf mf hardnested --blk <block number> <-a/-b> -k <key> -- <attacked block> <--ta/--tb>  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d2saOOS144kwJkzKHMmoloFe7vm707PIRCiaicib9qUb98HtfGdd9m9zFqQ/640?wx_fmt=png&from=appmsg "")  
  
  
这样，就可以从标识符中逐块提取所有信息。唯一的缺点是需要一段时间。  
  
  
请注意，Proxmark3有一个名为  
autopwn  
的强大功能：它会自动执行所有操作，这样您就可以专注于更重要的事情。  
  
  
**（六）DarkSide攻击**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
但是，如果您不知道任何密钥；而读卡器又受到安保人员的严密监视，该怎么办？在这种情况下，DarkSide攻击就能帮上忙了！  
  
  
这种攻击也可以利用PRNG的弱点，根据错误信息从比特中恢复密钥。  
  
  
这种技术的一个明显缺点是需要大量时间，但你不必用它来恢复整个标识符：在得到一个密钥后，你就可以进行hardnestd或nested攻击！  
  
  
运行指令：  
hf mf darkside  
。  
  
  
**（七）从读卡器中提取密钥**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
如果上述攻击都不成功，你可以尝试直接从读卡器中提取密钥。最简单的方法是使用Flipper Zero。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d27BcE3ULgSx0iaF01EteqELIm20dibwYkEu84AKoZAyfPTTLRVVDhaEBg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTXc6SwZiatYbo1o0TWp09d2jOlziaNTJk9knPo9YD9xWQNrsFWlDn1oYmDQ8ibfHmsZ17aUDLcuJcbw/640?wx_fmt=png&from=appmsg "")  
  
  
要从捕获的数据中提取密钥，可使用mfkey32[4]或者Flipper Lab[5]（基本相同，但更方便），并在上述攻击中使用提取的密钥。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、防护措施**  
  
正如您所见，Crypto1可以说是非常不安全的。当然，您可以对  
“  
魔术”卡进行检查（这将有效防御部分渗透攻击），但目前唯一可靠的解决方案是改用更先进的Mifare标识符（如Mifare Plus或Mifare DESFire）。  
  
  
顺便说一句，Mifare DESFire EV1已经被成功攻击过[6]，如果您希望您的PACS是安全的，请使用Mifare DESFire EV2、EV3等。  
  
  
注：有关此次攻击的更多信息，请参阅Carlo Meijer和Roel Verdult撰写的报告[7]。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、相关链接**  
  
****  
  
[1]https://hackmag.com/security/hacking-mifare/  
  
[2]https://hackmag.com/security/pacs-rfid-hack/  
  
[3]https://github.com/zhovner/proxmark3-1/blob/master/client/default_keys.dic  
  
[4]  
https://github.com/equipter/mfkey32v2  
  
[5]  
https://lab.flipper.net/  
  
[6]  
https://www.youtube.com/watch?v=ZSrOq40z1i8  
  
[7]http://www.cs.ru.nl/~rverdult/Ciphertext-only_Cryptanalysis_on_Hardened_Mifare_Classic_Cards-CCS_2015.pdf  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
