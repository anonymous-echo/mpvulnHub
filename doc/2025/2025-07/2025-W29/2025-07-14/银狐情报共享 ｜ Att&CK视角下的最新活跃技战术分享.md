> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583802&idx=2&sn=6f8be3f0ba840c2d458eeaa11dbefaf7

#  银狐情报共享 ｜ Att&CK视角下的最新活跃技战术分享  
威胁情报中心  嘶吼专业版   2025-07-14 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
概述  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RFOccUKcsRfYb7MADoD4hX4vFicBcNZoU8ovswJKFicDMXYSnNP1ibtn3ibaNicmuGlUodFI8ibAVoIdSJ2ccRKgyp5g/640 "")  
  
近年来，银狐针对国内企业数据资产及个人终端的定向攻击频发  
。  
通过  
进行  
敏感信息窃取，  
控制  
系统  
操作  
聊天  
应用  
以  
社工  
工程学  
为  
核心  
开展  
金融诈骗活动  
，  
已  
成为当前严重威胁企业/个人安全的攻击团伙之一  
。  
  
腾讯安全作为国内兼具云管端安全产品与威胁情报能力的综合性安全厂商，同时深度协同腾讯生态产品打击银狐钓鱼攻击，具备核心威胁感知优势。目前腾讯安全在银狐基础IOC检测、行为TTPs防护、驻留项和防御规避技术检测及清理等方面积累大量独家方案，经个人与企业客户场景充分验证有效。为联合更多安全厂商和企业安全部门打击银狐钓鱼攻击，我们将持续分享银狐团伙的最新情报和攻防技术方案，共同护航产业互联网安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DC72Via3tCEcbTQw6wMAvEPO1Ijq6dQPRXpFJmS9ewhgwxvibpMSmybKtTXqIRohV0ibxLLuhjuWFoibFeJuoibCfAA/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8GbHk6zNbA7ZTsrxmakzwpK8Gdqib9rVft8Kw8ibibqHvlPbvp7GSHmJkKUEdBHycciaLW0M2ZrSiaBeSjiaCsdsEIoQ/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gLF138RWfSgpJRQJRxgF5z5bW4tSJz3jpZrU4icI7L0ticzSdhxNAmf0w/640?wx_fmt=png&from=appmsg "")  
  
本文  
我们  
将  
通过  
公开  
近期  
银狐  
攻击  
过程  
中  
活跃  
技战术  
TTPs  
（  
战术、技术  
、  
步骤  
）  
，  
总结  
特点  
供  
业界  
参考  
。  
  
银狐  
攻击  
过程  
技战术  
使用  
丰富  
（  
attck  
矩阵  
黄色  
标记  
）  
，  
本文  
我们  
着重  
对  
其  
活跃  
使用  
且  
对抗  
激烈  
的  
技战术  
（  
attck矩阵  
红色  
）  
其进行  
总结  
。  
其中  
某  
技战术  
手法  
首次  
对外  
披露  
（  
使用文件关联  
  
+  
  
设备映射  
  
+  
  
PendingFileRenameOperations机制实现绕过安全软件无痕启动  
）  
。  
同时  
，  
我们  
也发现  
银狐  
开始  
结合  
R  
oot  
kit  
来  
进一步  
做  
更  
深层  
的  
系统  
潜伏  
和  
对抗  
检测  
，  
我们  
将  
在  
之后  
系列  
文章  
中  
再次  
同  
业界  
分享  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gXOmibtzZiaPfZ3TTFOTalIrajJDk4iajTTv1ef0TzUtpYMr12y9ThzKTg/640?wx_fmt=png&from=appmsg "")  
  
  
01  
  
银狐特性总结  
  
传播方式多样  
  
以  
钓鱼  
攻击  
，  
水坑  
攻击  
，  
第三方  
软件  
捆绑  
传播  
为主  
。  
通过社交工程邮件、即时通讯工具充分利用社会工程学、时事热点（*名单，*吃瓜，*税务，*票据等）投递恶意文件  
。  
通过仿冒（有道，酷狗，向日葵，Telegram，Google，DeepSeek等）合法网站植入恶意软件，定向诱导工具需求人群下载  
。  
  
  
攻击目标精准  
  
针对  
财务  
，  
税务  
，  
人事  
，  
运维  
等  
企业  
关键  
核心  
人员  
展开  
定向  
攻击  
，  
窃取  
核心  
机密  
权限  
，  
长期  
控制  
主机  
伺机  
开展  
金融  
诈骗  
活动  
。  
  
  
技术手段复杂  
- 白  
利用  
：  
使用  
合法带数字签名的程序进行白利用（传统DLL劫持，.net appdomain劫持，trueupdat  
e  
解释工具等），加载执行恶意模块代码。或直接将具备远控功能的软件C2武器化  
。  
  
- 内存  
注入  
：  
将恶意代码通过各类  
技术  
手段  
（远线程，Apc，Context，PoolParty等）注入合法进程（explorer.exe，lsass.exe，wusa.exe，tracerpt.exe，regsvr32.exe，dllhost.exe等）的内存空间中运行，隐藏自身恶意代码  
。  
  
- 载荷  
隐写  
：  
将恶意代码隐藏于非可执行文件（如图文、视频、文档）或注册表中，通过特定解析逻辑提取并执行  
。  
  
- 安全  
对抗  
激烈  
：  
通过技术手段（BYOVD，系统防火墙，  
网络  
策略  
，  
WDAC策略，安全软件VT兼容考虑  
，  
安全软件  
进程  
打开  
权限管控  
兼容  
考虑  
）关闭或干扰安全防护软件正常运行，修改系统配置使其无法检测恶意行为  
。  
  
- 持久化  
创新  
：  
除  
通过  
启动  
目录  
，  
注册表  
R  
un  
，  
服务  
，  
计划任务  
等  
方式  
持久化  
外  
。  
还通过  
UserInitMprLogonScript  
  
跟随  
系统  
启动  
。  
同时  
为了  
进一步  
绕过  
安全  
软件  
检测  
，  
创新  
式  
将  
启动  
目录  
进行  
劫持  
，  
使用文件关联+虚拟  
设备  
映射+PendingFileRename  
Operations  
机制实现  
绕过  
安全  
软件  
无痕启动  
，  
极具  
创新性  
。  
  
版本迭代快速  
  
通过  
样本  
增肥  
躲避  
云  
查杀  
，  
绕过  
部分  
安全  
软件  
快速  
检测  
机制  
。  
每日  
生成  
大量  
新变种  
，  
通过  
注册  
大量  
云  
设施  
，  
频繁  
更新  
C  
2  
信息  
以  
躲避  
安全  
厂商  
围剿  
。  
  
02  
  
初始访问（Initial Access：TA0001）  
  
- 水坑攻击（Drive-by Compromise：T1189）  
  
  
  
        银狐  
主要  
使用  
M  
S  
I  
，  
E  
X  
E  
两种  
类型  
伪装  
常见  
的  
安装包  
应用  
。  
通过  
仿冒  
工具  
站  
S  
E  
O  
后  
，  
诱导  
受害者  
下载执行  
，  
常见  
伪  
类  
应用  
包括  
，  
P  
D  
F  
工具  
，  
W  
P  
S  
，  
酷狗  
，  
向日葵  
，  
浏览器  
，  
飞书  
等  
。  
同时  
银狐  
也  
通过  
仿冒  
特定  
应用  
人群  
使用  
应用  
（  
虚拟  
币  
，  
T  
G  
，  
V  
P  
N  
等  
软件  
）  
进行  
精准  
投放  
，  
用于  
定向  
窃取  
虚拟币  
等  
资产  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWXzkrBBiatWAiaRDW2sPmTv1j0FbwWibURTf4BgttdFLdGcibJA22BO2uH1ZsHLQ1WX45CNTA3D1unS8Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWXzkrBBiatWAiaRDW2sPmTv1jkUNqJVVu2e2M5libgEpGKovd18l7SAqsGAfnrBan5YsXibaSgoyDev8g/640?wx_fmt=png&from=appmsg "")  
  
  
- 钓鱼攻击 （Phishing：T1566）  
  
        银狐  
擅长  
使用  
热点  
类  
新闻  
开展  
钓鱼  
，通过具有诱惑性  
（  
吃瓜  
，  
税务  
，  
薪酬  
，  
票据  
等  
）  
的钓鱼正文内容，诱导被害者  
下载  
点击  
（  
msi  
，  
exe  
，  
chm  
，  
vbs  
，  
bat  
）  
等  
恶意  
附件  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gfRhP6GWYvXAnL5p0lvwiafxjmu9Ee7ib1ibRI1cM5r8SxF1yOofCt4SGg/640?wx_fmt=png&from=appmsg "")  
  
  
  
03  
  
诱导执行（Execution：TA0002）  
  
- 用户执行（User Execution：T1204）  
  
整理  
银狐  
常见类伪装恶意载荷名如下。一旦受害者  
主动  
点击恶意附件，  
银狐  
后门  
则会在系统内  
开展  
进一步隐蔽对抗，持久化驻留  
。  
随后  
银狐  
攻击团伙对被害者  
主机  
展开持久控制，  
伺机  
实施  
金融  
窃密  
/  
诈骗  
过程  
。  
<table><tbody><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing:border-box;vertical-align:middle;padding:0px 7.2px;border-width:1px;border-style:solid;border-color:rgb(203, 205, 209);background-color:#a5c8ff;"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">MSI伪装类</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing:border-box;vertical-align:middle;padding:0px 7.2px;border-width:1px;border-style:solid;border-color:rgb(203, 205, 209);background-color:#a5c8ff;"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">EXE伪装类</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing:border-box;vertical-align:middle;padding:0px 7.2px;border-width:1px;border-style:solid;border-color:rgb(203, 205, 209);background-color:#a5c8ff;"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">钓鱼类主题</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">kugou_20.0.31_174.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">搜狗输入法 V53.33.66.exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*名单</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">YoudaoDict_fanyiweb.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">sogou_gaunwang_v_15.4.exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*吃瓜</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">ToDesk_Daas_v1.1.0.1.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">Telegram Desktop.exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*税务</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">Yiwaiwai Build Vers_cn_15689_19.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">新DeFi智能挖矿团队话术.exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*资料</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">SunloginClient_CN_pl_15.17603_x64.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">谷歌.exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*发票</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">AnyDesk_pl_Setuop.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">Google_GPT_brovvsewers_v2.4.18 .exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*票据</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">ChromeSetup.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">DeepSexploration_AGI.exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*社保</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">WPS办公软件 v56.63.23.msi</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">sky64.24.exe</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">*效果/方案/</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr><tr style="height:27px;"><td data-colwidth="155" width="183.13333333333333" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">...</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="228" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">...</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td><td data-colwidth="118" width="210.26666666666668" style="box-sizing: border-box;vertical-align: middle;padding: 0px 7.2px;border-width: 1px;border-style: solid;border-color: rgb(203, 205, 209);"><p style="text-align:left;line-height:1.3;margin-top:3pt;margin-bottom:3pt;margin-left:0pt;margin-right:0pt;"><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;" data-font-family="default"><span leaf="">...</span></span><span style="font-size:11pt;font-weight:normal;font-style:normal;color:#333333;letter-spacing:0pt;mso-font-width:100%;vertical-align:baseline;"><o:p></o:p></span></p></td></tr></tbody></table>  
历史  
情报  
：  
[暗流涌动：钓鱼木马再来袭](https://mp.weixin.qq.com/s?__biz=MzI5ODk3OTM1Ng==&mid=2247510281&idx=1&sn=6c73d4eb6460f6d7fbca307897b245e1&mpshare=1&scene=21&srcid=0709RnRsz7YN8dhItC04PPoP&sharer_shareinfo=11f754147d3fbdc31ecb4c7a7133b323&sharer_shareinfo_first=11f754147d3fbdc31ecb4c7a7133b323&color_scheme=light#wechat_redirect)  
  
  
  
04  
  
防御规避（  
Defense Evasion：TA0005）  
  
  
白利用  
- 传统软件DLL劫持白利用（Hijack Execution Flow：T1574）  
  
     腾讯混元大模型技术点解释：  
  
       Windows系统加载程序时，需要调用动态链接库（DLL）（相当于程序的“工具包”）。但系统有个“弱点”：加载DLL时，会按固定顺序搜索目录——优先从程序自己的文件夹（比如你安装的QQ目录）找，找不到再去系统目录（比如C  
:  
\Windows\System32）。  
  
       攻击者就钻这个空子：伪造一个和系统DLL同名/或应用程序自身需要的“假DLL”（比如lpk.dll、ws2_32.dll），放到程序的文件夹里。当程序运行时，系统会先加载这个“假DLL”，而“假DLL”里藏着木马的代码——程序以为自己在用系统工具，实际上被木马控制了。  
  
例如下图利用迅雷白模块，  
通过合法签名软件DLL劫持，执行最终恶意载荷  
。  
装载同目录XLFSO.dll，XLFSO.dll进一步装载mt.dll，最终  
装载同目录内非PE文件mi.jpg。查看mi.jpg可知文件头为一段shellcode，进一步执行其内部  
Embedded PE后门  
。  
  
主程序具有合法签名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gicXBuibgzg3LyBiba0QzctSb17ga2ekSztoj07EicvuSyQHpcCRynTiaWDA/640?wx_fmt=png&from=appmsg "")  
  
经过DLL双层劫持后装载外部非PE图片mi.jpg文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3g8tQ1r4aVrDu87xYyfMJ8JAIwPibWmenGCldfmaHyc7Z0cA4icEG5JmZQ/640?wx_fmt=png&from=appmsg "")  
  
mi.jpg图片文件本质为shellcode  
装载器+  
Embedded PE的恶意后门。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gkJN0iczAPUssSXK1dkU4ibAa5uV8I7iaZ1qWvyNw5S7Lc59TqUkfyaDjQ/640?wx_fmt=png&from=appmsg "")  
  
后门最终外联C2地址：  
12-18.qq-weixin.org  
。  
通过  
该  
域名  
不难  
看出  
，  
银狐  
为了  
躲避  
安全  
厂商  
围剿  
，  
进一步  
隐蔽  
其  
c  
2  
通信  
过程  
，  
使用  
到  
的  
恶意  
c  
2  
资产  
仿冒  
了  
国内  
知名  
软件  
域名  
。  
正常  
情况  
下  
，  
普通  
人  
很难  
发现  
该  
域名  
下  
的  
异常  
流量  
通信  
行为  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gDb60lQMxsJBaBRP8DibvWgAlMaVuOlic4ziaKyu3MGQ9HWSTv1nygCtMg/640?wx_fmt=png&from=appmsg "")  
  
- NET白文件AppDomainManager劫持（Hijack Execution Flow：T1574）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
腾讯混元大模型技术点解释：  
  
    .NET程序运行时，会通过AppDomainManager（应用程序域管理器）来创建和管理“应用程序域”（隔离代码执行的沙盒）。攻击者通过篡改这个“管理者”，可以让它在创建域时执行恶意逻辑。攻击者可通过修改.NET程序的配置文件或环境变量，让程序加载自定义的AppDomainManager程序集（负责管理.NET应用程序域），从而在程序启动时执行恶意代码。  
  
  
      如下  
案例  
，  
银狐利用Microsoft WSE（UevAppMonitor.exe）  
的  
白  
程序  
，配置其  
程序  
同目录下同  
模块  
名  
的  
config文件  
，  
配置  
中appDomain  
ManagerAssembley  
字段  
  
      当该程序执行时，  
WSE  
程序进一步尝试加载目录下配置的ureboot.Commands.exe程序集，  
ureboot.Commands.exe  
恶  
意程序集模块最终使用0xEE进行动态解密外部n180yhty.mdb文件，  
对其  
进行装载后  
，  
执行  
后  
门远控外联C2；  
同时  
恶意  
代码  
还  
具备恶意代码注入系统进程内实现进程守护的功能。  
  
  
      攻击者  
篡改  
后的  
appDomainManager劫持  
信息  
，  
白  
利用  
文件  
为Microsoft WSE白程序  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gxhyuHjcMyicb1aHxM7tIeHjBlGoXTpVtTMjBpyGNIpRfth6sicTPSwTg/640?wx_fmt=png&from=appmsg "")  
  
      ureboot.Commands  
.  
e  
x  
e  
程序集  
使用0xEE作为key  
解密  
恶意  
代码  
后  
进行  
二  
阶段  
恶意  
载荷  
装载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gVlZzMfNqSQb7yfxTSwzsqAypYr66CNicsF4ZO8Vicxic3Ne8hx5fibdLDg/640?wx_fmt=png&from=appmsg "")  
  
  
      同时  
最终  
后门  
通过  
将核心注入系统白进程  
（  
tracerpt  
.  
e  
x  
e  
）  
实现  
进一步  
隐蔽  
自身  
目的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gI4LrBgSsqOWKfNIBbqFRFYibxufbba9WXMI84u9uEFu9QQZV8tATliaw/640?wx_fmt=png&from=appmsg "")  
  
最终外联C2：156.152.19.180  
，  
该  
资产  
来自  
境外  
，  
使用  
该类型  
资产  
可  
进一步  
增加  
其  
团队  
溯源  
难度  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gTP2GDz3BQVEUlf2q9k2XkuguH74osLenjlyfGuqI6NKcLPZibeib5jsQ/640?wx_fmt=png&from=appmsg "")  
  
- TrueUpdate白利用（System Binary Proxy Execution：T1218）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
     腾讯混元大模型技术点解释：  
  
         
TrueUpdate是IndigoRose公司开发的打包安装工具，支持通过Lua脚本自定义安装逻辑（如文件释放、注册表修改、网络请求等）。木马（如“银狐木马”）利用其打包隐蔽性、脚本自定义能力及密码保护机制，实现对系统的隐蔽渗透与持久控制。  
  
  
  
      如下  
图  
，  
银狐  
木马  
利用  
TrueUpdate  
加载  
外部  
l  
u  
a  
脚本  
da  
t  
文件  
，  
进一步  
装载  
外部  
jpg  
，  
xml  
非  
P  
E  
中  
的  
恶意  
后门  
载荷  
。  
由于  
整个  
恶意  
代码  
加载  
过程  
涉及  
白文件  
+  
非  
P  
E  
文件  
。  
检测  
能力  
弱  
的  
安全  
软件  
将  
无法  
检测  
到  
过程  
中  
的  
恶意代码  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gdPZ76dI67p96U8lIfDf1BuetEWXTic4N0iatmlmqTPfbTUD1WdS0tksQ/640?wx_fmt=png&from=appmsg "")  
  
- 合法软件白利用武器化（Remote Access Tools：T1219）  
  
腾讯混元大模型技术点解释：  
  
    合法远程软件（比如TeamViewer/edr或上网管理类软件）本身有强大的远程控制功能：能跨网络连接、传输文件、甚至控制键盘鼠标。木马直接自己写一套远程控制功能很麻烦，不如“偷懒”——直接利用现成的合法软件，既能绕过系统限制（比如防火墙可能默认允许这些软件联网），又能伪装成正常操作（用户看到是熟悉的软件界面，不容易怀疑）。  
  
    简单说，就是木马把原本用来远程控制的合法软件改造成“木马工具”，让它变成黑客的“遥控器”，偷偷控制别人的电脑。  
  
使用IPGUARD  
（  
历史情报  
[情报速递20240516｜“银狐”钓鱼团伙利用某安全软件管控功能进行攻击](https://mp.weixin.qq.com/s?__biz=MzI5ODk3OTM1Ng==&mid=2247506972&idx=1&sn=a544deeea2b7ec9b213ac980ba5b46b4&scene=21#wechat_redirect)  
  
）  
，固信管理。由于该系列软件具备合法的远程控制功能，且具备驱动级权限，银狐团伙积极将其武器化使用  
。  
  
如下图所示，伪装税务app的程序运行后，会安装名为pobus64的某终端  
E  
D  
R  
管控产品，由于该软件具备远程管理功能，攻击者将其武器化做C2工具使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gX9R7zrJpicsb4LACuWqaQEWDHFCGmicFRJMbUyzaZzVvDd61opwIVbFQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3g2wTqcsgiaLmicIkpqHRdg5jMtqzvA1N3zPZ113B3njhmIESJ4ibeGuDLA/640?wx_fmt=png&from=appmsg "")  
  
  
安全对抗  
  
      银狐执行时，  
为了  
实现  
在  
安全  
软件  
监控  
下  
持续  
运行  
，  
会尝试使用多种方式对抗安全软件  
。  
包括断网/防火墙策略部署绕过安全软件云策略监控；安装VT功能软件利用兼容性绕安全软件  
主动  
防御  
；  
利用  
安全  
软件  
兼容  
考虑  
注入LSASS进程  
对抗  
安全  
进程  
；通过BYOVD利用获取内核权限深度对抗；利用WDAC策略禁用安全软件等  
。  
目标直接结束掉安全软件或者屏蔽掉安全软件的部分能力，  
达到  
长期  
控制  
主机  
下  
不被  
查杀  
。  
- BYOVD（Exploitation for Privilege Escalation：T1068）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
腾讯混元大模型技术点解释：  
  
    BYOVD（Bring Your Own Vulnerable Driver，自带漏洞驱动）是一种内核级攻击技术，核心逻辑是：攻击者利用系统中已存在的、带漏洞的合法驱动程序（比如系统自带或知名软件附带的驱动），通过漏洞获取内核权限，绕过用户态安全软件的防御，直接在内核层面执行恶意操作（如关闭杀毒软件、窃取数据）。  
  
    一些公开热门的BYOVD开源利用项目：  
  
    https  
:  
//github.com/BlackSnufkin/BYOVD  
  
    https  
:  
//github.com/ZeroMemoryEx/Blackout  
  
    https  
:  
//github.com/Helixo32/NimBlackout  
  
    https  
:  
//github.com/Hagrid29/BYOVDKit  
  
    https  
:  
//github.com/BlackSnufkin/GhostDriver  
  
      如  
下图  
银狐在系统内安装存在漏洞的wsftprm.sys的白驱动程序  
，由于  
该  
内核文件存在漏洞，加载后可通过在应用层发送相关IOCTL  
实现  
结束任意  
受  
内核  
程序  
保护  
的  
软件  
（  
例如  
安全  
软件  
）  
进程  
。  
银狐  
团伙  
将  
此类型  
内核  
模块  
插件  
化  
使用  
，  
可  
有效  
获取  
内核  
权限  
，  
将  
对抗  
战场  
进一步  
从  
应用层  
牵引  
到  
了  
内核  
态  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gKYZibS8tIXv9jiaRJLA6k2O9Zz71L1A1Zfc8qibsz5zq8qA8k0Oia0Hdhw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gSZNaeSEBibMj888llwMwrUiaiaciaH0ygtuzPpLhM9xxm7fHWicLREQeMCQ/640?wx_fmt=png&from=appmsg "")  
  
- 网络策略对抗（Impair Defenses：T1562）  
  
  
  
腾讯混元大模型技术点解释：  
  
    木马的核心目标是长期潜伏、不被发现、完成黑客任务。断开/限制网络能减少“被追踪”和“被拦截”的风险；限制安全软件流量则让防御工具“变瞎变哑”，无法有效反击。两者结合，木马就能更隐蔽地控制电脑，实现窃取数据、破坏系统等目的。  
  
如  
下图  
银狐使用netsh设置错误的本地IP连接静态地址  
策略  
，从而导致网络暂时中断，  
实现  
屏蔽  
安全  
软件  
云端  
检测  
/  
防护  
策略执行后续  
恶意行为  
；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3ghqVfppMPfmDMfCC5BvibOrcYJ3Mq8tcVibw1OTojiciaCOnrsjJwj49LIQ/640?wx_fmt=png&from=appmsg "")  
  
- WDAC策略滥用（Impair Defenses：T1562）  
  
  
  
腾讯混元大模型技术点解释：  
  
    WDAC（Windows Defender Application Control，Windows Defender应用程序控制）是微软推出的一项系统安全功能，核心作用是控制哪些程序能在电脑上运行。它通过“白名单”机制，只允许明确受信任的程序（如系统自带工具、企业认证软件）执行，阻止未知或恶意软件运行，常用于企业环境保障系统安全。  
  
    木马利用WDAC策略对抗安全软件，本质是“借刀杀人”——用系统自带的安全功能，反过来限制安全软件的运行。它通过篡改“允许运行的程序清单”，让安全软件成为“被禁止的对象”，而木马自己则被加入“白名单”，从而实现长期潜伏、不受监控的攻击目标。  
  
      如下图，银狐木马释放  
名为  
SIPolicy.  
p7b  
的  
WDAC策略配置  
bin  
文件  
。  
对  
其  
进行  
解码  
后  
查看其内容可知，其中配置了安全软件相关进程  
/  
模块  
/  
目录  
下  
的  
拒绝  
策略  
，  
攻击者  
意图使用系统WDAC策略禁止安全软件启动  
，  
从而  
躲避  
查杀  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gMF5pxRcxD0nePSLHhcLic8Uj4rbSl6alBO3IF6IwmgulaDh9xenMYhA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gvib4PWic7WzVD6cZTY3oKPjKZ30dowQBeuibE1tIicKFyI3ISnaRzeGYMg/640?wx_fmt=png&from=appmsg "")  
- Windows Defender策略滥用（Impair Defenses：T1562）  
  
腾讯混元大模型技术点解释：  
  
    Windows Defender会定期扫描系统文件，如果发现病毒（恶意程序），会隔离或删除它。病毒为了存活，必须让Defender“跳过”自己的位置——这就需要用到PowerShell的Add-MpPreference -ExclusionPath命令（或类似的Set-MpPreference命令）。这个命令的作用是：告诉Defender“这个路径里的文件不用扫描”。  
  
如  
下图  
，  
银狐  
使用  
powershell.exe Set-MpPreference -ExclusionPath "C:\", "D:\", "E:\", ..., "Z:\"  
将  
所有  
目录  
添加  
到  
排除  
目录  
，  
进而  
在  
Windows Defender  
扫描  
时  
对  
其  
自身  
恶意  
文件  
模块  
进行  
白名单  
放行  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gUt400vic1TGP1LCBZwsRN6IKgG0mxGHkxty26ydyMe1RQS0icfHW43lQ/640?wx_fmt=png&from=appmsg "")  
- VT程序滥用（Impair Defenses：T1562）  
  
腾讯混元大模型技术点解释：  
  
    Intel VT（Intel Virtualization Technology）是CPU级硬件辅助虚拟化技术，ntel VT通过VMX模式隔离、VMCS控制、EPT内存虚拟化等核心技术，为终端安全软件提供了硬件级的安全隔离与性能保障。其核心优势在于其全维度监控：覆盖API调用、进程行为、内存操作等多个层面。  
  
部分  
安全  
软件  
使用  
VT（Intel Virtualization Technology，英特尔虚拟化技术）  
实现  
更  
底层  
的  
系统  
安全  
行为  
监控  
。  
该  
功能  
属于  
CPU级别的硬件辅助虚拟化技术  
，  
比操作系统内核态Ring 0  
  
更底层  
，  
属于Ring -1层  
，  
兼容性问题  
更加  
复杂  
  
。  
银狐  
充分  
挖掘  
安全  
软件  
兼容  
考虑  
下  
的  
临时  
退出  
场景  
。  
如下图  
，  
银狐  
利用  
W  
E  
G  
A  
M  
E  
反作弊  
系统  
使用  
V  
T  
虚拟化  
时  
，  
部分  
安全  
软件  
对  
W  
E  
G  
A  
M  
E  
兼容  
考虑  
下  
的  
退出  
场景  
，  
从而  
绕过  
其  
主动  
防御  
策略  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3g0q4AOvz3v9f4ECibgzibw9Xkial7UMLwVa5UX1OYREaVqYEW2XrrxsZvA/640?wx_fmt=png&from=appmsg "")  
- 增肥/混淆（Obfuscated Files or Information：T1027）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
     腾讯混元大模型技术点解释：  
  
         
木马要绕过安全软件的“围追堵截”，除了隐藏自身代码、伪装成正常文件，还会用“体积增肥”的手段——把自己的文件体积变得异常大（比如从几KB涨到几百MB），让安全软件“看不上”或“认不出”，从而顺利进入电脑潜伏。  
  
       银狐木马母体可达上百MB，同时也会将一些关键的恶意模块进行单独的增肥，意图使用该方式来规避安全软件云查杀，躲避部分安全软件快速查杀策略。  
同时  
，  
银狐  
也  
使用  
各  
中  
代码  
加壳  
，  
混淆  
手法  
进一步  
隐藏  
特征  
，  
  
历史  
情报  
（  
[情报速递20240509｜银狐钓鱼团伙2024年1-5月攻击趋势](https://mp.weixin.qq.com/s?__biz=MzI5ODk3OTM1Ng==&mid=2247505390&idx=1&sn=1c6f2e9556ad9ab20a7e2a6549e31107&scene=21#wechat_redirect)  
  
）  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gcGmTgSukBKVUnV5aLuoOETuvn1fedgzL7ogWIicdTlTdLVbZNyeDxmg/640?wx_fmt=png&from=appmsg "")  
- 注册表/图片隐写（Obfuscated Files or Information：T1027 ）  
  
腾讯混元大模型技术点解释：  
  
    隐写术是木马的“隐形外套”，它将恶意代码（如木马程序、控制指令）隐藏在注册表内，或图片文件（如PNG、JPG）的“像素缝隙”或“文件结构”中，让安全软件误以为这是“正常图片”，从而跳过扫描。  
  
如下  
图  
，  
银狐  
将  
恶意  
C  
2  
载荷  
填充  
到  
注册表  
特定  
位置  
，  
使用  
外部  
L  
oader  
在  
启动时  
将其  
从  
注册表  
内  
读取  
后  
进一步  
装载  
，  
使用  
该  
方式  
可  
有效  
避免  
安全  
软件  
对其  
核心  
恶意  
功能  
代码  
的  
检测  
。  
  
历史  
情报  
（  
[情报速递20240524｜银狐团伙使用核酸检测退费发票信息主题的钓鱼攻击增多](https://mp.weixin.qq.com/s?__biz=MzI5ODk3OTM1Ng==&mid=2247507553&idx=1&sn=b4a901fce1ee34994739f9bd81844e47&scene=21#wechat_redirect)  
  
）  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gDrEcYH1lUe5WlMKiaaYfwicWe5z6sibNiaicoBMUVha5kRNLceMbpOmqlsg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3g3zFtCyKF9VFkWZRrjqC7E3bn93VWw2vlETNaJn98Qk7A8RRqq1iaKdQ/640?wx_fmt=png&from=appmsg "")  
  
  
05  
  
持久化（TA0003）  
  
- 自启动位置（Scheduled Task/Job：T1053，Modify Registry：T1112，Create or Modify System Process：T1543）  
  
  
  
腾讯混元大模型技术点解释：  
  
    服务（Services）：随系统启动的“隐形守护者”  
  
    启动目录（Startup Folder）：用户登录的“自动触发器”  
  
    注册表启动项（Registry Run Keys）：系统级的“隐身开关”  
  
    计划任务（Scheduled Tasks）：定时/事件的“精准开关”  
  
    这四种方式均为Windows合法功能，木马通过“伪装”成正常组件（如服务、启动程序、定时任务、注册表配置），绕过用户和安全软件的常规检测。更关键的是，多重机制叠加（如服务+注册表+计划任务）形成“复活链”——即使其中一个被清除，其他机制仍能重新激活木马，实现“野火烧不尽”的持久化控制。  
  
        银狐  
持久化  
形式  
多样  
，  
充分  
利用  
注册表  
，  
服务  
，  
启动  
目录  
，  
计划任务  
等  
。  
除此外  
，  
也看到  
对于计划任务  
等  
启动路径  
上  
，银狐  
也  
常使用一些字符凭借/混淆手法，意图躲避一些终端查杀匹配策略。  
总结  
银狐  
主要  
使用  
以下  
几种  
方式  
来  
混淆  
路径  
，  
干扰  
查杀  
。  
- 引号包围单个字符检测(如"c"h"r"m"s"t"p")  
  
- 引号包围路径分隔符检测(如"\"r")  
  
- 空格引号干扰路径解析检测  
  
如  
下图  
文件名  
使用  
引号  
进行  
拼接  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3g6uDibCmlX9raDcvaszNibicic89nM5MDoQTBUue1EichBdao0c5Xamib7qSg/640?wx_fmt=png&from=appmsg "")  
  
可  
排查  
以下  
相关  
位置  
确认  
是否  
存在  
异常  
启动  
项  
：  

```
注册表：
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\run
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\Explorer\run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run

服务：
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\[服务名]\ImagePath

计划任务：
%WinDir%\system32\Tasks\*
%WinDir%\Tasks\*
%WinDir%\SysWOW64\Tasks\*(WoW64系统)

启动目录：
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*
%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup\*
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*
%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\*
```

- UserInitMprLogonScript（Boot or Logon Initialization Scripts： T1037.001）  
  
腾讯混元大模型技术点解释：  
  
    UserInitMprLogonScript 是 Windows 注册表中的一个用户级键值（路径：HKEY_CURRENT_USER\Environment），它的作用是：当用户登录系统时，自动执行该键对应的程序或脚本。  
  
    简单说，它就像一个“登录触发器”——你每次输入密码登录电脑，系统都会检查这个键，如果里面有路径，就会自动运行里面的程序。  
  
如下图  
，  
银狐  
写入  
UserInitMprLogonScript  
内  
恶意  
载荷  
实现  
持久化  
执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gPw9eEII5ia66GpPW6Pp1emned2otvc2tSzJ6hCbSrJltbiblM0nF7x7Q/640?wx_fmt=png&from=appmsg "")  
  
- 篡改启动目录（Boot or Logon Autostart Execution ： T1547）  
  
  
  
腾讯混元大模型技术点解释：  
  
    攻击者通过篡改系统内注册表Shell Folders\Startup的根本目的，是让系统“误以为”恶意文件夹是合法的启动目录。系统启动时，会按照注册表的指示，去恶意文件夹里找程序运行，而不会怀疑这个文件夹的“真实性”。  
  
    这种劫持方式的隐蔽性和危害性都很强，因为它利用了Windows系统的“信任机制”，绕过了安全软件的常规检测。  
  
如  
下图  
，  
攻击者  
劫持  
启动  
目录  
到  
恶意  
银狐  
载荷  
位置  
内  
实现  
隐蔽  
执行  
。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gPzica0GgulU7SRPduJibuLywtnC6yMnVzl8gzFgwUsradic3ibYjmaMv7Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gdYCyhrcWR5sutdhFdZw8mD10xHxpuOnkq4VZicFc6F0ezkncfWKh2YQ/640?wx_fmt=png&from=appmsg "")  
  
- 文件关联+虚拟设备映射+PendingFileRenameOperations机制无痕启动（Event Triggered Execution：T1546，Modify Registry：T1112 ，Boot or Logon Autostart Execution：T1547）  
  
  
  
腾讯混元大模型技术点解释：  
  
    Windows文件关联：  
  
    Windows中注册表HKEY_CLASSES_ROOT\[文件扩展名]\shell\open\command很关键，系统用注册表路径来记录“文件类型→程序”的对应关系，用于在打开指定类型文件时，调用对应的程序。  
  
   
  
    Windows新增磁盘设备：  
  
   
   Windows中注册表DosDevices项是Windows系统的“盘符字典”，记录了“盘符名字”和“存储路径”的对应关系。通过修改这个字典里的“名字”（比如把F  
:  
改成G  
:  
），系统就会给对应的存储设备分配新的盘符，实现“新增盘符”的效果。  
  
   
  
    Windows-PendingFileRenameOperations作用：  
  
    PendingFileRenameOperations是Windows系统的“文件操作待办清单”，专门记录暂时无法完成的文件重命名/删除任务，等下次开机时自动执行。它的存在解决了“文件被占用时无法操作”的问题。主要包括以下常见场景：  
  
    软件安装/卸载：安装程序需要删除旧版本文件，但旧文件被系统进程占用，就会写入PendingFileRenameOperations，等重启后删除。  
  
    系统更新：Windows更新时需要替换系统文件，但文件正在被使用，就会记录到PendingFileRenameOperations，重启后完成替换。  
  
    临时文件清理：系统或程序生成的临时文件，需要删除但被占用，也会通过PendingFileRenameOperations延迟处理。  
  
   
  
    Windows-PendingFileRenameOperations操作时机：  
  
    PendingFileRenameOperations的操作时机早于驱动加载，其执行发生在会话管理器（smss.exe）启动后、驱动加载前，是Windows系统启动流程中前置的文件操作步骤，确保驱动加载时文件系统的完整性。  
  
我们  
首次  
披露  
银狐  
使用  
的  
一些  
独特  
的  
持久化  
手法，  
通过  
创建  
虚拟  
设备  
，  
将  
StartUp目录  
上层  
目录  
映射  
到  
新的  
设备  
盘  
位置  
，同时充分结合文件关联以及  
PendingFileRenameOperations  
机制实现隐蔽无痕启动。  
银狐  
充分  
利用  
相关  
系统  
特性  
，  
组合  
实现  
了  
一套  
自创  
的  
无痕持久化过程  
，  
以  
实现  
绕过  
安全  
软件  
监控  
隐蔽  
持久化  
执行  
，  
详细  
过程  
如下  
：  
  
如下图  
：  
银狐写入公共下载目录下  
一个  
随机  
后缀  
的  
W  
O  
F  
L  
D  
文件  
+  
后门  
exe  
程序  
，正常  
情况  
下  
系统  
重启  
后  
木马  
无法  
再次  
执行  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3ggmickNlaHbUvPj3xjzwcxPhdlr9sD3QXfu4QYVicedibBPicsKLsWGwUrg/640?wx_fmt=png&from=appmsg "")  
  
        银狐  
创建.wofld  
随机  
文件后缀的关联启动，当有.wofld文件执行时，  
会  
关联  
使用  
后门exe  
打开  
。  
可以  
看到  
该位置  
由于  
写入  
的  
是  
随机  
类型  
后缀  
的  
打开  
关联  
，  
并非  
篡改  
敏感类  
E  
X  
E  
，  
D  
L  
L  
，  
L  
N  
K  
可执行  
类  
程序  
关联  
。  
所以部分安全软件出于用户体验考虑，  
对  
该  
处  
弱  
风险  
行为  
并不会拦截  
，  
此时  
木马  
无法  
实现  
重启  
持久化  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gLGXtWaHpYjkZHx6Ep0kfSpdEnzliaPmqIwSg3kSVAqlkiaYUY9Pnaic0g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gwNyAwd6ic7e3oPGZ2CH7EN8WfWpJ084YaJqovKibqss70VnqY5kJibyQg/640?wx_fmt=png&from=appmsg "")  
  
        银狐  
创建  
虚拟  
设备  
O  
盘  
，  
将其  
映射  
到  
系统  
S  
tart  
  
U  
p  
启动  
目录  
的  
上层  
，  
此时  
木马  
依旧  
无法  
完成  
持久化  
启动  
，  
由于  
仅仅  
是  
创建  
了  
一个  
P  
rograms  
目录  
的  
映射  
操作  
，  
该  
动作  
并  
不  
敏感  
，  
该弱风险行为安全软件通常会放行  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gb9QmrXic5EWKv3bzNloCvzVjdkKFjH68icofQWdgw0Le5ReBMlaCyXvA/640?wx_fmt=png&from=appmsg "")  
  
银狐  
最终  
利用  
PendingFileRenameOperations  
机制  
，  
实现  
在  
开机  
启动  
时  
将  
随后  
wofld  
类型  
后缀  
文件  
写入  
O  
盘  
下  
S  
tart  
up  
目录  
内  
。  
可以  
看到  
，  
此处  
写入  
启动  
路径  
位置  
为  
O  
:  
\  
S  
atrtup  
下  
，  
由于  
该  
路径  
并不  
敏感  
，  
所以虽然部分安全软件监控了  
PendingFileRenameOperations  
操作  
，但依旧会  
对其  
放行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3g44hlicBicWF4ETib9JDP2VPOQfVyMPWeRKLSQzNEnwknzjicT4JiaAiajwAw/640?wx_fmt=png&from=appmsg "")  
  
由于  
O  
盘  
下  
S  
tart  
up  
此时  
正好  
被  
映射  
到  
系统  
盘  
启动  
目录  
，  
随机  
类型  
文件  
在  
开机  
时  
被  
写入  
启动  
目录  
，  
随机  
类型  
文件  
有机会  
得到  
执行  
。  
又  
由于  
随机  
后缀  
文件  
的  
打开  
被  
关联  
到  
下载  
目录  
内  
的  
木马  
E  
X  
E  
程序  
，  
故  
系统  
拉起  
执行  
了  
恶意  
后门  
。  
  
由于  
是  
在  
开机  
过程  
完成  
的  
O  
盘  
映射  
目录  
文件  
写入  
，  
且  
该  
操作  
由  
W  
indows  
会  
话管理器（smss.exe）  
完成  
。  
该  
模块  
启动  
时间  
早于  
安全  
软件  
驱动  
加载  
。  
最终  
绕过  
了  
部分终端安全  
软件  
严  
防  
死守  
的  
启动目录监控。  
同时  
木马  
启动  
成功  
后  
，  
会  
再次  
删掉  
启动  
目录  
内  
已  
存在  
的  
随机  
后缀  
启动  
文件  
，  
从而  
导致  
整个  
启动  
过程  
在  
事  
后  
完全  
无感知  
。  
  
分析  
整个  
过程  
，  
银狐利用系统内3处  
与  
启动  
项  
无关  
的  
弱风险篡改操作，绕过安全软件检测/阻断过程。最终组合实现了一个超级隐蔽，且稳定的无痕持久化方式。  
  
  
06  
  
影响（TA0040）  
  
  
      银狐团伙以高度定向性、技术复杂性和社会工程欺骗性为核心，借助其不断演进的对抗性技术组合  （安全对抗、内存驻留、持久化创新、 隐蔽性增强、利用合法服务通信）及多维度诱骗策略  （如热点时事钓鱼、热门应用伪装），已经构建起“传播-渗透-控制-窃取-诈骗”的完整攻击链路。  
  
      当  
银狐  
木马  
成功  
植入  
系统  
，  
攻击者  
则  
进一步  
尝试  
控制  
主机  
。  
通过  
远程  
控制  
主机  
桌面  
，  
进一步  
尝试  
窃密  
，  
操作  
主机  
开展  
诈骗  
等  
行为  
，  
被攻击主机可能出现以下系统异常行为。  
- 社交软件大量发送虚假诈骗消息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gPwKMLrXBvnzgEQP6Hh0ZISBrwypqic3KsWOhltMgj2gYFaTPmZJgn5Q/640?wx_fmt=png&from=appmsg "")  
- 虚拟财产  
转账  
过程莫名其妙  
重  
定向到黑客账户内。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gZsXLmIXvsvDmtOvmSMmg048BmNXJbqSYJR02TMvhUNjKjqvmehvgBQ/640?wx_fmt=png&from=appmsg "")  
- 系统桌面鼠标莫名自动点击，摄像头自动打开。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gzNUZ0Tq951kJibAn4uyEV2nAYNOAaDyIQ4hSqf5f0UQ1fUfC8vma9icg/640?wx_fmt=png&from=appmsg "")  
- 系统内  
部分系统进程频繁外联可疑地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6AoQM3RKCWWXPFaVgs8GYZMZ75lmFg3gocqDpkicMnIrxuLyNcIVfcXN7fK0d4LOhPMf8ib2gyY2u8KnuyibSY8Mg/640?wx_fmt=png&from=appmsg "")  
- 系统内工作资料存在打开翻动痕迹。  
  
- 系统内软件/系统账号被频繁异常登录。  
  
- 系统安全（  
本地  
防火墙，杀毒软件）防护运行异常。  
  
- 任务管理器中的可疑随机进程CPU占用异常，无法结束。  
  
07  
  
防护建议  
  
- 提高警惕，谨防钓鱼攻击：切勿随意打开来历不明的链接、点击接收未知来源的邮件附件或下载安装非可信渠道的应用，对微信群、QQ 群等社交媒体传播的非官方通知和程序保持高度警惕。  
  
- 谨慎处理敏感信息：涉及个人敏感信息输入（如银行卡号、手机验证码等）或钱财转账时，务必谨慎核对信息来源与用途，确保操作安全合法。  
  
- 及时部署安全软件：建议部署终端安全软件，开启钓鱼防护和实时监控功能，并保持系统与安全软件版本及时更新，以具备最新防护能力。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wpkib3J60o287jwk8LWD9icmgWlahS21WBibH0Iz3x2kLShrmHpicmyoLLZjhkG6s61yDMgXpJ74WhrDYlWupFxzKg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
