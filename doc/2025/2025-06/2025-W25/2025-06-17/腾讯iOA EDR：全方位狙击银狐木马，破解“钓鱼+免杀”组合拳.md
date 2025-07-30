> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247527256&idx=1&sn=5ec2b3e00647bca31d0f43634fa31435

#  腾讯iOA EDR：全方位狙击银狐木马，破解“钓鱼+免杀”组合拳  
 腾讯安全   2025-06-17 10:31  
  
近年来，  
一款名为“银狐木马”（又称“游蛇”）的恶意程序在国内及亚太地区悄然肆虐，其攻击目标精准锁定政府机构、金融、医疗及制造业的高价值岗位人员（如财会、高管等），  
以狡猾的伪装手段和复杂的技术链条，成为企业安全防御体系中的“隐形炸弹”。  
  
  
据悉，这是一种具有高度隐蔽性和复杂功能的恶意软件，“毒如其名”，  
善于伪装，就像一只狡猾的狐狸，潜伏在财税/政务领域，常常伪装成“财会发票”“税务稽查通知”“企业福利补贴名单”等文件，以迷惑用户点击。其传播渠道广泛，包括微信群、钓鱼邮件、各类社交媒体等，还利用搜索引擎竞价排名、SEO引流等手段诱导用户下载，使用户防不胜防。  
  
“狡诈银狐”持续进化  
  
入侵手段层出不穷  
  
  
  
自2019年首次曝光以来，  
银狐已迭代多个版本，持续增强免杀对抗与持久化驻留能力。最新变种在攻击手段上更为狡猾和复杂，它充分利用人性弱点，伪装吸引用户点击下载到 PC 上，并通过多阶段内存加载、白加黑劫持、驱动级对抗等先进技术手段，巧妙地规避杀软检测，形成了  
“传播-驻留-窃密”的全链路攻击闭环。一旦获得终端权限，银狐或潜伏监视，长期收集用户数据，或直接操控受害机器拉群传播木马和实施二维码诈骗，直接威胁企业核心资产与个人隐私安全，堪称企业安全的“隐形炸弹”。  
  
  
当前，银狐入侵手段层出不穷，最新版本通过四大手段突破传统防御：  
  
- 一是伪造官方机构通知，借时事热点钓鱼。银狐团伙擅长结合政策节点伪造“税务局”“财政部”等官方文件，例如在税务稽查高峰期，通过邮件、短信发送钓鱼链接，页面仿真度极高，诱导受害者点击后自动下载木马程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256AquvQH3MdTgXwxjLnTfI1JHJcfoQ2sdzDvtDU2kqD37MHTD1DibsvMA/640?wx_fmt=png&from=appmsg "")  
  
假冒税务局通知  
  
- 二是社交平台广撒网，钓鱼文件秒变“病毒快递”。通过社交渠道发送钓鱼文件和二维码，直接在微信群、QQ群等群组中传播虚假链接，迅速扩大感染范围。2025年上半年，已有多家企业员工受害，银狐团伙通过工作群传播诈骗信息，进而盗取员工财产。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256ibBWkicEaSjkLqgpa3qkN7TTS8XHv4IdredWhwKf4gMJuIHvamgcHz8Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256Z4eAjZ2JvZYP5vB2hRptia98AIJiaCI0kDdeicdNb8GKO7DLz08CJyZKA/640?wx_fmt=png&from=appmsg "")  
  
钓鱼二维码/微信群转发  
  
- 三是高仿办公软件下载页，精准捕捉职场需求。银狐团伙还深谙国内办公习惯，复刻官网构造各类软件下载仿冒页面，如紧跟时事仿冒DeepSeek本地部署等常见办公软件，未仔细分辨的用户极易不慎下载木马。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256R0Kib5LXoDRg6paYrtPCic7WFz22tjk6jJfRsUvfcPibics3rwkpL7ySmg/640?wx_fmt=png&from=appmsg "")  
  
紧跟时事，仿冒DeepSeek本地部署  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256qleP4EtvSDEHXJahHibtezGD77YzN1sGaiauycr2GayicoFfcQqH8h7LA/640?wx_fmt=png&from=appmsg "")  
  
各种仿冒办公软件  
  
- 四是云存储平台隐身术，令溯源追踪难上加难。为规避安全监测，银狐将恶意程序伪装成“行业报告”“设计素材”“学习资源”等文件，托管至知名网盘或云服务商的对象存储服务（OSS，Object Storage Service）。由于云平台IP动态分配且资源链接分散，安全团队难以通过传统IP封禁或域名拦截手段溯源，形成“下载即中毒，中毒难追责”的攻击闭环。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256YKM2Zv4er3eU8mWvsKQ544Y2SJibhlDr3icPMAVAgc3jyabTv1ibqfqbg/640?wx_fmt=png&from=appmsg "")  
  
网盘中挂载的银狐  
  
腾讯iOA EDR实战  
  
助力企业“精准猎狐”  
  
  
  
第一幕：伪装正常软件悄然潜入  
  
  
近期，腾讯iOA团队就帮助某游戏开发公司成功定位并阻断银狐攻击。公司内部人员在网络上下载了某软件安装包，当用户点击安装时，腾讯iOA EDR的内核探针瞬间捕获异常行为：未签名的lets-3.12.3.exe正释放可疑的msi安装包，此处就已触发了EDR告警，可以清晰地看到，EDR界面详细地展示了攻击详情，包括进程命令行、文件名、文件路径等信息。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256v1mfpueSX4ia5M06tuEnoicZE4fP0NiaYE5mQ0CeXGMmK4hIiciaSTRIxaQ/640?wx_fmt=png&from=appmsg "")  
  
  
具体来说，银狐木马伪装入侵，在初始阶段即被iOA及时发现。  
首先，安装包签名过期。EDR的文件信誉系统采集到该安装包无有效签名，同时关联图引擎追溯到文件源于Edge浏览器的异常下载，形成“浏览器-恶意文件-释放行为”的初始攻击链证据。  
其次，检测到连锁恶意操作。可疑安装包在执行时触发了连锁恶意动作——msiexec.exe应用调用cmd.exe启动了hotdog.exe，该程序正是被银狐改造的黑客工具Nidhogg，该工具正尝试通过“进程保护”绕过常规杀毒软件检测，iOA及时发现并帮助用户快速处置。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256MdoCmMBghPpqrIapTKibDbQWAIpzFyvyFRW563wgzOyiaVfVMqaIfjFg/640?wx_fmt=png&from=appmsg "")  
  
安装包签名过期  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256dLOUbWur5MXKYFuobK3ibicmY2oHcjzzZH3WHLywDZZvcic7mLeehXiaRQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc2561RWtD1fMavSicDtum2Elnudh9icwdVFvV6EHy4xuJBX0YVmZtx2hKyoQ/640?wx_fmt=png&from=appmsg "")  
  
连锁恶意操作  
  
  
第二幕：内核级探针捕获异常行为链  
  
  
与此同时，银狐木马在入侵电脑的C:\Program Files (x86)\Windows NT目录下植入tprotect.dll驱动，并创建自启动服务“CleverSoar”，准备为下一步非法外联做准备，谁料一系列的动作都被iOA纳于眼底，立刻触发了一条EDR告警。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256wIad2tAuawptbJgOicPoIdWjaaqfZkV2wsBs3wk5rBuGwouktXTgRJg/640?wx_fmt=png&from=appmsg "")  
  
  
接下来，EDR持续发威，异常行为被持续关联，溯源铁证逐步浮现。  
msiexec → cmd → hotdog的异常情况被完整记录，命令行参数显示正执行“process add 6772”等攻击指令；同时，银狐木马写入注册表的隐藏计划任务被EDR及时发现并实时拦截，尽管银狐木马注册表项描述伪装为“Microsoft”，但路径与时间戳仍然暴露了其恶意属性，进一步坐实了攻击证据。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256n5oAyEicphBy9IedTLZ9fLY4pGc2R1K0lbQLiaNndVNvqdgeGK4Rq1uA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256xwdCSSrrkPnol1gyMMq0N1Jg5hcmq7OiaXGhMLY5QVoo4rfMbhxxtSQ/640?wx_fmt=png&from=appmsg "")  
  
进程调用链条全链路展示  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256tWpq6KWzhhvV98xbhviaL0niaTEAPiaibjKcTOzVJInzicdJmoia8VXa0XHg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256fwqFSYU2qbDTn2RL5xic4l2Vrlff8mWFtI9C8D5rJzvM5FMfgTTHicibw/640?wx_fmt=png&from=appmsg "")  
  
持久化证据确凿  
  
  
第三幕：多维度检测阻断攻击闭环  
  
  
同一时间，银狐木马所关联的runtime.exe进程尝试连接域名8004.twilight.zip，一旦外联成功，PC将被黑客远程控制，千钧一发之际，EDR通过腾讯威胁情报库精准识别，确认外联端为银狐C2控制端，并及时在控制台产生对应告警信息。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256a0oY1pl4TY4jY5FTvH38iboibZM4IicX0xeet6sgrlFMLb9mROjibbx1mA/640?wx_fmt=png&from=appmsg "")  
  
  
EDR防御矩阵同步启动：  
  
- 终端行为阻断：iOA成功拦截了MSI文件的释放，终止了恶意进程hotdog.exe，并将其隔离至沙箱。同时，通过识别tprotect.dll驱动的签名时间与系统环境的冲突，并借助iOA图引擎追溯到文件源头，形成了完整的初始攻击链证据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256StsdVxpwnuYzRmU9sM2h7yX4JUSjDuBC7eayJ8s3hD3lQIibPZUbM2g/640?wx_fmt=png&from=appmsg "")  
  
- 持久化清除：安全研判介入后，迅速下发终端响应任务，删除了注册表Tree路径下的隐藏任务项，并修复了被篡改的计划任务配置。此外，还停止了CleverSoar服务并清除了驱动文件，有效阻断了内核级驻留。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256UYQeZRy34TswUsl3jKSDQg0HjNiaKxppQw03WQVLcdbPrA5MT9nicDOw/640?wx_fmt=png&from=appmsg "")  
  
- 外联行为阻断：EDR基于威胁情报实时阻断了C2域名解析，禁止可疑进程联网，并生成了详细的网络访问日志，记录了恶意IP的通讯企图。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenD3iaTVRrA91dxG3G5Pc256F5UzyUl1M371cCWn3jlbzUAWgXkl4MKZDRqwVlSU910iaESwVdmAibiaA/640?wx_fmt=png&from=appmsg "")  
  
  
通过以上自动化手段，  
iOA构建起一整套智能防御体系，并在本次实战攻防演练中成功抵御银狐木马的高强度攻击，充分展现了  
“主动防御+智能响应”的创新安全防护理念。  
  
- 全链路可见性：完整记录从钓鱼文件下载到C2通信的全流程事件，通过溯源图直观呈现攻击链各环节，为安全复盘提供坚实证据。  
  
- 多层级对抗能力：内核级探针+行为分析+威胁情报，形成立体防御体系，有效应对银狐木马如“多阶段内存加载 + 驱动级对抗”等高级攻击手段。  
  
- 自动化响应效率：腾讯iOA EDR通过预设响应策略，实现“秒级检测+分钟级处置”，显著降低安全团队的应急响应压力。  
  
攻防对抗  
  
持久战未歇  
  
  
  
网络安全的本质是攻防对抗，这是一场永不停歇的持久战，需要行业各方协同应对。针对当前银狐木马的日益猖獗，腾讯iOA团队联合科恩实验室特别提醒：  
  
- 提高警惕，谨防钓鱼攻击：切勿随意打开来历不明的链接、点击接收未知来源的邮件附件或下载安装非可信渠道的应用，对微信群、QQ 群等社交媒体传播的非官方通知和程序保持高度警惕；  
  
- 谨慎处理敏感信息：涉及个人敏感信息输入（如银行卡号、手机验证码等）或钱财转账时，务必谨慎核对信息来源与用途，确保操作安全合法；  
  
- 及时部署安全软件：建议部署企业级终端安全软件，开启钓鱼防护和实时监控功能，并保持系统与安全软件版本及时更新，以具备最新防护能力。  
  
同时，腾讯iOA为不同规模的用户提供了两套银狐木马防护解决方案：  
  
- 针对500点以下的中小企业用户，  
腾讯iOA基础版永久免费开放，提供完整的病毒查杀、钓鱼防护、终端加固等安全能力，满足中小企业的终端安全防护需求。  
  
- 针对500点以上的中大型企业，腾讯iOA也可以提供免费试用，在基础安全防护能力之上，还额外提供  
终端检测与响应EDR模块，配套  
腾讯安全专家在线研判服务，让各类高级安全威胁无所遁形！  
  
扫描下方海报二维码，即可快速开通腾讯iOA基础版，永久免费使用！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdenMTJLCVh66al5pP8Ym7u47yYqnxUqTwicXgvXGAtBSDIqUjEuokH1E7QnLHJ07biax8X3QTYmbNzHg/640?wx_fmt=png&from=appmsg "")  
  
  
  
- END -  
  
  
**构建数字安全免疫力，守护企业生命线**  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247511216&idx=1&sn=ec603700621fc67da8814477de2b782a&chksm=c055c19cf722488abbb453fc1038f90779c712635aca34eb01c887195f904d3556d57e5a9a4a&scene=21#wechat_redirect)  
  
**从内网护卫到零信任尖兵：腾讯iOA炼成记**  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247513958&idx=1&sn=b33c5e0bfe28e0ab8a47e1766b734bfa&chksm=c055da4af722535c000bffe32181556db159bb2eb1b3c5813c9886ba624d0fecbec7dd79521d&scene=21#wechat_redirect)  
  
**EDR能力全国第一！腾讯 iOA以100%覆盖率通过ATT&CK V14 测评**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247525147&idx=1&sn=42160fd1f5b53bfa4c3ec5f1b635b77b&scene=21#wechat_redirect)  
  
**腾讯云凭借零信任iOA连续两年入选Gartner®市场指南代表厂商**  
  
  
  
