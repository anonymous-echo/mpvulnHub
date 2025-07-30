> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAwODU5NzYxOA==&mid=2247506263&idx=1&sn=8ee3c5bca7df5b02d1e19a33b209232c

#  “银狐木马病毒”来势汹汹！华为 HiSec Endpoint帮助客户成功精准斩断远程控制，守护企业数据资产  
 华为安全   2025-07-14 13:10  
  
今年以来，“银狐木马病毒”攻击活动愈演愈烈。国家计算机病毒应急处理中心和计算机病毒防治技术国家工程实验室在中国境内连续捕获一系列针对中国网络用户，特别是财务和税务工作人员用户的木马病毒。经过分析后发现这些病毒均为“银狐”家族木马病毒变种。  
  
  
  
  
**什么是‌“银狐”木马病毒？******  
  
‌  
  
银狐又名 “游蛇”、“谷堕大盗”，是一款专门针对政府、高校及企事业单位等关键行业等从业人员进行攻击的木马病毒变种之一。银狐木马能够获取受害者的计算机控制权限并长期驻留，通过远程控制受害者的计算机，窃取用户敏感信息，并通过监控受害者的日常操作，达到窃取隐私的目的，为后续实施诈骗等行为铺路。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EjJibicwCQS5QbdFxQBgn7iaqoTXtB614A1ueC0XPQicbNeknX1ww8eZ5aNDBgibWlZ2GGMJRgnLBqNcEMbtEmL2I2g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**银狐木马攻击过程：利用诱导内容，远控木马实施钓鱼攻击**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EjJibicwCQS5QbdFxQBgn7iaqoTXtB614A1r4OV9C2TdQ3TAlfSROVVcJnRIXueJ8301EJJplYogB4Mxm1XRv57rw/640?wx_fmt=png&from=appmsg "")  
  
**01**  
  
**传播阶段：**  
银狐木马通常利用微信、电子邮件、钓鱼网页等渠道进行传播。利用紧迫感诱导用户立即执行恶意程序。传播给受害者。  
  
**02**  
  
**诱导执行阶段：**  
用户一旦点击下载并解压这些伪装成正常工作文件的压缩包，运行其中的恶意可执行文件或脚本，木马便开始在终端静默执行，建立与攻击者恶意C&C服务器的连接通道。  
  
**03**  
  
**持久驻留与恶意操作阶段:**  
木马成功植入后，通过“白+	黑”（白文件+黑dll）的攻击手法规避常规杀毒软件的监测，长期潜伏和窃取信息  
  
  
**银狐木马的防御难点：“毒如其名”，善于伪装**  
  
  
自2022年开始活跃以，银狐已迭代多个版本，持续增强免杀对抗与持久化驻留能力。最新变种在攻击手段上更为狡猾和复杂，它充分利用人性弱点，伪装吸引用户点击下载到PC上，并通过多阶段内存加载、白加黑劫持、驱动级对抗等先进技术手段，巧妙地规避杀软检测。  
  
  
**1、指数级增长的变种数量，银狐特征捕捉难度大**  
********  
  
  
银狐木马通过模块化设计和自动化工具批量生成变种，仅2024-2025年间就衍生出“游蛇”“谷堕大盗”等数十种变体，加载器技术迭代周期缩短至数周，指数级增长的变种数量，使得银狐特征难以捕捉，检测难。  
  
  
**2、多阶段加载与内存驻留技术，规避静态扫描**  
********  
  
  
银狐通常通过压缩包（如ZIP、RAR）分发，解压后释放看似正常的lnk, vbs或msi文件。这些文件非PE文件,脚本通常混淆加密,可以在第一时间先规避AV查杀。  
  
  
**3、白加黑与高级注入技术，伪装正常软件悄然潜入，致盲安全软件**  
********  
  
  
**1）合法签名程序劫持，导致放行恶意行为******  
  
银狐利用带有合法数字签名的文件程序（如Avira, usbmon, iobit）作为掩护，安全软件因信任合法签名，可能放行恶意行为。  
  
  
**2）断链注入，规避检测******  
  
银狐通过APC注入、反射DLL注入、进程挖空等方式将代码注入合法进程（如浏览器、办公软件），切断进程父子关系，规避基于进程链的检测。  
  
  
**3）致盲安全软件******  
  
银狐会试图摘除安全软件的监控功能，或者致盲系统ETW（Event Tracing for Windows，内置事件跟踪机制），让安全软件即使在正常执行的过程中也无法感知木马的动作。  
  
  
**4、多样化C2通信与隐蔽通道，对抗流量检测**  
********  
  
  
银狐将命令与控制服务器（C2）信息隐藏在合法网站（如GitHub页面、云存储链接）中，木马定期访问这些站点获取指令。流量混杂于正常访问。同时通信数据使用AES加密或自定义算法加密，并伪装成HTTPS、DNS等合法协议流量，难以被流量识别拦截。  
  
  
华为HiSec Endpoint关键方案和竞争力:矩阵式防御体系直击 “银狐” 要害  
  
  
华为HiSec Endpoint构建了一套全方位、多层次的矩阵式防御体系，为用户的终端安全保驾护航。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EjJibicwCQS5QbdFxQBgn7iaqoTXtB614A1XZtHAic1QO6shteyGl7vwwgTlk7D7lzbzyfFqqicQ0N8H9G1ib26MQwIw/640?wx_fmt=png&from=appmsg "")  
  
  
**防御层一:**  
  
**AI钓鱼检测，精准识别未知钓鱼木马。**  
  
  
基于机器学习和自然语言处理技术，分析学习海量恶意/良性样本，建立钓鱼特征和行为基线，能够精准识别未知钓鱼URL和“简历、发票、报税”类钓鱼木马样本。  
  
  
**防御层二:******  
  
**第三代静态检测引擎CDE，检测率业界领先。**  
  
  
采用MDL（Malware Detection Language，恶意软件检测语言）专有病毒语言，以少量资源精准覆盖海量变种；集成专有在线神经网络等高精度AI算法，赛可达测试静态检出率达99.39%。  
  
  
**防御层三:******  
  
**混淆脚本检测，查杀非PE恶意文件。**  
  
  
针对银狐木马采用压缩包释放的非PE恶意文件，逃避AV查杀。Hisec Endpoint支持脚本内容动态解密还原脚本真实攻击意图，基于频繁模式挖掘算法形成恶意脚本特征集，提升无文件命令行和加密脚本行为检测率。  
  
  
**防御层四:******  
  
**高级躲避检测，精准识别避检测行为。**  
  
  
针对银狐木马利用白加黑或高级注入方式利用系统白进程做后门通讯，逃避检测。Hisec Endpoint基于端云协同的创新溯源图，支持进程注入、注册表劫持、白文件捆绑等多种逃避检测技术及白程序滥用技术，精准识别银狐躲避检测行为。  
  
  
**防御层五:**  
  
**Shellcode检测，拦截外部通信。**  
  
  
HiSec Endpoint产品在可疑内存事件上打点,比如内存分配，权限更改，内存执行,  准确识别Shellcode指令，配合内存陷阱技术抓取银狐木马的控制服务器地址，拦截外部服务器通信。  
  
  
**防御层六:**  
  
**快速内存扫描，精准识别Gh0st木马变种。**  
  
  
实时识别出白加黑木马的可疑内存区块，对内存区域使用高速相似度扫描算法以精确识别银狐的各种Gh0st木马变种。  
  
  
**防御层七:**  
  
**端网联动检测恶意/异常连接。**  
  
  
HiSec Endpoint支持与防火墙联动。防火墙检测出银狐访问恶意域名后，发送告警事件到云端乾坤，乾坤基于聚合和关联生成威胁事件，定位失陷主机，借助安全响应编排能力，调用该失陷主机EDR接口，结束银狐进程，隔离恶意文件。  
  
  
此外，HiSec Endpoint同时可联动乾坤综合关联溯源，自动还原攻击意图与链条，检测多主机横向移动及高级持续隐蔽攻击。在iMaster NCE-Campus 集成部署模式下，能实现身份化认证，动态调整用户准入与访问权限，保障企业资产安全。  
  
  
成功防御案例：帮助省交通行业客户成功检测“银狐病毒”  
  
  
近日，某省单位虽部署终端安全软件，内网主机仍遭钓鱼攻击感染 “银狐病毒”，对业务造成严重影响。现网部署华为HiSec Endpoint后，发现该病毒将恶意代码注入VSSVC 和svchost进程，执行后遭黑客远程控制。HiSec Endpoint 识别Shellcode指令，结合内存陷阱技术抓取控制服务器地址，成功拦截外部通信，精准斩断远程控制，助力客户守护企业数据资产。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EjJibicwCQS5QbdFxQBgn7iaqoTXtB614A1gA79ENF5HKeQQv1MicrvdQdEDib8PY17HBWX2XVAV9BQG069B4Xbdg6A/640?wx_fmt=png&from=appmsg "")  
  
“银狐”告警事件图  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EjJibicwCQS5QbdFxQBgn7iaqoTXtB614A1L0oKDMPWoLwgfqYsSvK97iaOQKQbTatrHKdo1TX3ePWrPQ9TGF137hg/640?wx_fmt=png&from=appmsg "")  
  
“银狐”病毒溯源图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EjJibicwCQS5S4Iic7OicXpradWN3a7brUDLBCU7O1k5nTUrFgdoakWIMiaibfjDTlGJxkA9IPibEcNwicKfTq0oDFdxMA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/iaRDyoND55HiaXH5T0PpCBxBaLPUictKiceuLyz1shIgvHqRQLS3VLbCfk0eIGdQ3OQiaqDTOykOkDKAnur82wNH8UQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击**“阅读原文”**  
，了解更多华为网络安全解决方案！  
  
