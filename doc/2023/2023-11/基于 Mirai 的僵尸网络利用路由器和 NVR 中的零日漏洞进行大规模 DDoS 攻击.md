#  基于 Mirai 的僵尸网络利用路由器和 NVR 中的零日漏洞进行大规模 DDoS 攻击   
 网络安全应急技术国家工程中心   2023-11-27 14:53  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176lia2YbowVvkqcQrSYZAz242P6wYesicjYmmibBXTKrjEumGbtx36AG5oRZDakjJHD8lWCcg0Q9ZytsQ/640?wx_fmt=jpeg&from=appmsg "")  
  
一个活跃的恶意软件活动正在利用两个具有远程代码执行 （RCE） 功能的零日漏洞，将路由器和录像机连接到基于 Mirai 的分布式拒绝服务 （DDoS） 僵尸网络中。  
  
Akamai在本周发布的一份公告中说：有效载荷以路由器和网络录像机（NVR）设备为目标，使用默认管理员凭据，一旦成功就会安装Mirai变种。  
  
有关这些漏洞的详细信息目前还处于保密状态，以便这两家厂商发布补丁，防止其他威胁行为者滥用这些漏洞。其中一个漏洞的修补程序预计将于下月发布。  
  
网络基础设施和安全公司于 2023 年 10 月底首次发现了针对其蜜罐的攻击。攻击实施者的身份尚未确定。  
  
由于在命令控制（C2）服务器和硬编码字符串中使用了种族和攻击性语言，该僵尸网络被代号为InfectedSlurs，是2018年1月曝光的JenX Mirai恶意软件变种。  
  
Akamai表示，它还发现了更多似乎与hailBot Mirai变种有关的恶意软件样本，根据NSFOCUS最近的分析，后者出现于2023年9月。hailBot是基于Mirai源代码开发的，其名称源自运行后输出的字符串信息'hail china mainland'。  
  
Akamai详细介绍了一种名为wso-ng的网络外壳，它是WSO（"web shell by oRb "的缩写）的 "高级迭代"，与VirusTotal和SecurityTrails等合法工具集成，同时在尝试访问时将其登录界面隐藏在404错误页面之后。  
  
Web shell 的显著侦察功能之一是检索 AWS 元数据，以便随后进行横向移动，以及搜索潜在的 Redis 数据库连接，从而在未经授权的情况下访问敏感的应用程序数据。  
  
微软早在 2021 年就表示：Web shell 允许攻击者在服务器上运行命令以窃取数据，或将服务器用作其他活动的助推器，如凭证窃取、横向移动、部署额外的有效载荷或动手键盘活动，同时允许攻击者在受影响的组织中持续存在。  
  
**参考资料：**  
  
https://thehackernews.com/2023/11/mirai-based-botnet-exploiting-zero-day.html  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
