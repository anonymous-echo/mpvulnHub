#  Day5-HVV Windows LPE 0day漏洞在暗网出售，可直接打穿系统   
原创 病毒獵手 童杭波  oldhand   2024-07-27 20:02  
  
                      
   
辛弃疾《青玉案·元夕》  
  
众里寻他千百度，蓦然回首，那人却在，灯火阑珊处  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/cy038mJgyib5yp70OmcYJQN8oeXicmuicuPw6ezVwgFvg6aSmAzOic7fZj9ic9tDzfyXzOuZoibhqaaMQ8DklJPsQ4Rw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**HVV搞了5天，大家累了，我们缓解一下，突然今天在网站看到一个售卖0day漏洞的帖子，恰逢最近HVV阶段，小心红队购买0day实施攻击。**  
  
一名威胁行为者声称正在出售新的Windows LPE 0-day。  
  
据威胁行为者称，成功率为   
98%。  
  
●价格:15万美元  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib5yp70OmcYJQN8oeXicmuicuPqeStEUx7mqeibdAQzY0LbL8H9MP9WBibkq6icemfwkXIBPTKWIEnrB1Aw/640?wx_fmt=png&from=appmsg "")  
# 一、hvv红队攻击  
  
  
(1) [已复现]1Panel面板前台SQL注入到网站功能RCE漏洞  
  
(2) [已复现]宏脉医美行业管理系统存在任意文件读取漏洞  
  
(3) [oday已复现]通达OA后台SQL注入  
  
(4) [已复现]致远OA ucpcLogin接口身份鉴权绕过漏洞  
  
(5) [0day已复现]致远互联FE协作办公平台某接口存在SQL注入漏洞  
  
(6) [未公开]深信服VPNsupersession存在远程代码执行漏洞  
  
(7) [已复现]拓尔思TRS媒资管理系统uploadThumb存在文件上传漏洞  
  
(8) [已复现]金和OA C6 GeneralXmlhttpPage存在SQL注入漏洞  
  
(9) [已复现]用友GRPA++cloud政府财务云selectGlaDatasourcePreview存在SQL注入漏洞  
  
(10) [已复现]JeePlus快速开发平台resetPassword存在SQL注入漏洞|  
  
(11) [[已复现]F-logicDatacube3存在命令执行漏洞  
  
(12) [已复现]创客零售商城系统存在文件上传漏洞  
  
  
【演练实时消息】  
  
【消息时间】：2024-07-27  
#  【消息标题】：百易云-资产管理运营系统-任意文件上传  
  
【消息详情】：百易云资产管理运营系统 comfileup.php 接口存在文件上传漏洞，未经身份验证的攻击者通过漏洞上传恶意后门文件，执行任意代码，从而获取到服务器权限。  
  
【演练实时消息】  
  
【消息时间】：2024-07-27  
#  【消息标题】：金慧-综合管理信息系统-SQL  
  
【消息详情】：由于金慧-综合管理信息系统 LoginBegin.aspx（登录接口处）没有对外部输入的SQL语句进行严格的校验和过滤，直接带入数据库执行，导致未经身份验证的远程攻击者可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
【演练实时消息】  
  
【消息时间】：2024-07-27  
#  【消息标题】：TOTOLINK-A6000R-RCE  
  
【消息详情】：TOTOLINK A6000R是一款性能卓越的无线路由器，采用先进的技术和设计，为用户提供出色的网络体验。其支持最新的Wi-Fi标准，可实现高速稳定的无线连接，适用于各种网络需求，包括流畅的高清视频流、快速的在线游戏和大规模文件传输。双频段支持让用户可以根据需求选择最佳的无线信号频段，确保网络稳定性和速度。此设备中的webcmd 函数中存在命令注入漏洞，攻击者可以通过webcmd 函数中的cmd参数包含命令，进行命令执行攻击。  
  
【演练实时消息】  
  
【消息时间】：2024-07-27  
#  【消息标题】：用友-U8-Cloud-SQL  
  
【消息详情】：用友U8 Cloud MeasureQueryFrameAction接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
# 二、蓝队防守  
## 1.社工钓鱼线索：  
  
通过跟踪威胁情报信息，在下载很多钓鱼木马供各位老爷尝尝，及时的封堵和识别。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib5yp70OmcYJQN8oeXicmuicuPuVIl1nMsrM2jZTRRJDtk8U5ov1Yz3pmZUoZx5ww28eiaN4zpwWotp7A/640?wx_fmt=png&from=appmsg "")  
  
  
## 2.蓝队封禁IP列表  
  
通过查询内部资料信息，将  
HVV2024的封禁的IP 信息分享给各位姥爷，请姥爷，慢慢用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib5yp70OmcYJQN8oeXicmuicuPRPjdnpc1bUKyPWRT6844009Dyt4ic2lmCAAVfRibYibmVStIwRaXiaHdvA/640?wx_fmt=png&from=appmsg "")  
  
  
# 三、 笑话  
  
无敌社会工程学渗透  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib5yp70OmcYJQN8oeXicmuicuPM443QGwwsj7buRgjAcprkYpWqvEhrYttbQhg1V0CCFyNZTW2YXKJaA/640?wx_fmt=png&from=appmsg "")  
  
# 四、 公众号  
  
团队成立于2016  
年，**WIS-HUNTER（中文全称智慧网络病毒猎手）**  
，拥有最全的信息安全服务内容；具备强大的安全研究团队，公司下辖多个实验室，其中杀手锏攻防实验室拥有大批漏洞发掘和分析人员，是独立发掘CVE  
和  
CNVD  
漏洞数量的团队；拥有覆盖  
8*N  
人的专业安全服务团队。  
  
**赖杨健******  
  
**WIS-HUNTER病毒猎手******  
  
**杀手锏攻防实验室******  
  
资深安全架构师  
  
18年以上安全行业工作经验  
  
曾供职于启明星辰、爱立信、阿朗、上汽等大型企业  
  
持有CISP-IRE, CISP-PTS,OSCP,CISSP国内国际安全证书  
  
持有CNVD国家漏洞库证书和CVE ID  
  
赖老师的学生所获得的CNVD证书：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib6S8yvh7wWG82X6YsMwTzfpxoodibamI9uvyJByU8McVepBFExmONTaoLtKQibuibkbEQssch3U8fNgQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
团队理念：  
  
【理念】  
  
**以小博大，技术是杀手锏。**  
  
【文化】  
  
1.  
明白人：**知其然，知其所以然**  
！不要迷惑于表象而要洞察事务的本质，要有文盲学习知识的心态，有时我们的学历，是我们学习过程中   
最大的障碍。  
  
2.  
出品人：**本人出品，必属上品**  
！有自我荣誉意识、追求卓越意识。乔布斯：人这辈子没法做太多事情，所以每一件都要做到精彩绝伦。  
  
