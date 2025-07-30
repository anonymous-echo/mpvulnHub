#  OWASP发布2025十大智能合约安全漏洞   
 中科天齐软件安全中心   2025-02-06 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51p00schCwC0OurOI9ZmlG7eIyYo2TQQRsOq6d1FQQKLqBlNWV4sfX4Q/640?wx_fmt=png&from=appmsg "")  
  
  
点击  
**蓝字**  
  
关注**中****科天齐**  
  
  
随着去中心化金融(DeFi)和区块链技术的不断发展，智能合约安全的重要性愈发凸显。在此背景下，开放网络应用安全项目(OWASP)发布了备受期待的《2025年智能合约十大漏洞》报告。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51RHjkXm3oiaJe64Cy5JKORKfRZ0VO1JUwAiblMdXqYQA6ViaPP2aBScuMw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
这份最新报告反映了不断演变的攻击向量，深入剖析了近年来的常见漏洞及缓解策略。旨在提升Web3开发者和安全团队的安全意识，为开发者、审计人员和安全专业人士提供宝贵的资源，以应对智能合约中最关键的安全漏洞。它还与其他OWASP项目，如《智能合约安全验证标准》(SCSVS)、《智能合约安全测试指南》(SCSTG)相互补充，为区块链生态系统的安全提供了全面的方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51ibLUIRtK3BvrvhxWqSVsaYIUkcFgic2YIABk6qOPwoG03YFwXgFjiae5A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**2023年至2025年的主要变化**  
  
  
  
2025年版榜单根据真实事件和新兴趋势更新了排名，并提供了新的见解。显著的变化包括新增了“价格预言机操纵”和“闪电贷攻击”两个独立类别，反映了这些漏洞在DeFi攻击中的日益普遍。  
  
  
与此同时，早期版本中较为突出的“时间戳依赖”、“Gas 限制问题”等漏洞已被替换或整合到更广泛的类别中，如“逻辑错误”。  
  
  
  
**2025年OWASP十大漏洞详解**  
  
  
  
**SC01：访问控制漏洞**  
  
  
访问控制漏洞仍然是智能合约中导致财务损失的主要原因，仅2024年就造成了9.532亿美元的损失。这些漏洞通常是由于权限检查未正确实施而产生的，以致未经授权的用户可以访问或修改关键功能或数据。一个典型案例是88mph的“函数初始化漏洞”，攻击者利用该漏洞重新初始化合约并获得管理员权限。  
  
  
**SC02：价格预言机操纵**  
  
  
操纵价格预言机(智能合约使用的外部数据源)可能会破坏协议的稳定性，导致财务损失或系统性故障。攻击者通常利用设计不良的预言机机制暂时抬高或压低资产价格。  
  
  
**SC03：逻辑错误**  
  
  
业务逻辑漏洞通常发生在合约未能正确执行其预期功能时。这些错误可能导致代币铸造错误、借贷协议缺陷或奖励分配错误。  
  
  
**SC04：输入验证缺失**  
  
  
未能验证用户输入可能使攻击者能够向智能合约注入恶意数据，导致意外行为或破坏合约逻辑。  
  
  
**SC05：重入攻击**  
  
  
重入攻击利用合约在完成自身状态更新之前调用外部函数的能力。这一经典漏洞在 2016 年的 DAO 攻击中被利用，导致价值 7000 万美元的以太坊被盗。  
  
  
**SC06：未检查的外部调用**  
  
  
当智能合约未能验证外部调用的成功时，可能会基于错误的交易结果假设继续执行，从而导致不一致或被恶意行为者利用。  
  
  
**SC07：闪电贷攻击**  
  
  
闪电贷允许用户在一个交易中无抵押借款，但可能被利用来操纵市场或耗尽流动性池。  
  
  
**SC08：整数溢出和下溢**  
  
  
当计算超出数据类型限制时，可能会发生算术错误，使攻击者能够操纵余额或绕过限制。  
  
  
**SC09：不安全的随机性**  
  
  
区块链的确定性特性使得生成安全的随机性具有挑战性。可预测的随机性可能会破坏依赖随机结果的功能，如抽奖或代币分配。  
  
  
**SC10：拒绝服务(DoS)攻击**  
  
  
DoS攻击针对智能合约中资源密集型功能，通过耗尽Gas限制或计算资源使其无法响应。  
  
  
  
**对现实世界的影响**  
  
  
  
OWASP 智能合约Top 10的编制基于《加密货币损失报告》等资源中记录的真实事件。仅2024年，就有149起事件被记录在案，造成了超过14.2亿美元的损失，其中访问控制漏洞(9.53亿美元)、逻辑错误(6300万美元)和重入攻击(3500万美元)是主要原因。这些数据凸显了在区块链开发中加强安全实践的紧迫性。  
  
  
随着区块链技术的成熟，攻击者利用其漏洞的方法也在不断演变，这也强调了Web3项目增强自身抵御潜在漏洞能力的重要性。  
  
  
文章来源：FreeBuf  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51R0XKjcAibdSQr5lA2KcqkdJpYDKybiaxmTviblBBfksHqMpCAibVyqME3w/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy515a8vgkkPrNfmJkyj9RAExU2x6hXJxRMzodgey3vGYFnj82rX61cNBA/640?wx_fmt=png&from=appmsg "")  
  
**往期阅读**  
  
****  
[7-Zip高危漏攻击者可绕过安全机制远程执行代码](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496213&idx=1&sn=41ff4ec3981ca43faad6cd4583c6b88a&scene=21#wechat_redirect)  
  
  
  
[重大产品更新！中科天齐2025年度产品重要升级](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496150&idx=1&sn=ba994a2df8756f457f0cdd018a461921&scene=21#wechat_redirect)  
  
  
  
[生成式人工智能对国家安全的挑战](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247495994&idx=1&sn=8845a0fabf92a490fad0d1859bb86d88&scene=21#wechat_redirect)  
  
  
  
[应用程序面临的LLM安全威胁以及5种缓解方法](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247495977&idx=1&sn=7f0a92b400bb36a72b61c074e2cd68c4&scene=21#wechat_redirect)  
  
  
  
[一文读懂“OWASP LLM应用十大风险”，洞悉最新安全态势](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247495963&idx=1&sn=8dcceb7e83fdb7f748e3dbc5b604cbc6&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51p00schCwC0OurOI9ZmlG7eIyYo2TQQRsOq6d1FQQKLqBlNWV4sfX4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy514EUvcicSictvboKEFPkkPToPBcXy5vS7Q6p4HKJPspX0vBZESukG59Dg/640?wx_fmt=png&from=appmsg "")  
  
软件源代码安全缺陷检测平台  
**软件安全 网络安全的最后一道防线**  
  
中科天齐公司由李炼博士创立  
  
以“中科天齐软件源代码安全缺陷检测平台  
  
（WuKong悟空）”为主打产品  
  
致力打造安全漏洞治理领域新生态的  
  
高新技术企业  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy518ubufwSKYd9dozxN0YhfdRFMFGdxibnyIBTST8QUDSZ1MbMn2RrzvOQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51ez3p8OtQPM3ULPC2Y9HoicxQkgkQ7BBsKJQ5oAEkP2aakp3ZYBNIbdA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy518ubufwSKYd9dozxN0YhfdRFMFGdxibnyIBTST8QUDSZ1MbMn2RrzvOQ/640?wx_fmt=png&from=appmsg "")  
  
**长按二维码关注我们**  
  
  
**联系方式：400-636-0101**  
  
**网址：****www.woocoom.com**  
  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51kiaaPKaB1K5zUnBjf683mJ7Vbjtiattkx13fTQfkCLsGVmZO61ChSmAA/640?wx_fmt=png&from=appmsg "")  
  
  
  
点击在看  
  
分享给小伙伴  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xx53Lt2eIAkBJLklNxgeSdUL0wbLYy51SHY46VcFFfmicfiahZu2m6AFMZ4CrRgwqKCVTaNYiaDP7xQIIJyQf7dSg/640?wx_fmt=gif&from=appmsg "")  
  
点击  
**阅读原文**，获得免费预约地址  
  
