> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTUzNzY3Ng==&mid=2247489178&idx=1&sn=da94d972d802ca4c55bf8dfd5a5cac85

#  漏洞预警|请尽快更新Windows微信到4.0版本  
 SecHub网络安全社区   2025-07-21 02:27  
  
****  
****  
****  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**免责声明**  
  
本文发布的工具和脚本，仅用作测试和学习研究，禁止用于商业用途，不能保证其合法性，准确性，完整性和有效性，请根据情况自行判断。  
  
如果任何单位或个人认为该项目的脚本可能涉嫌侵犯其权利，则应及时通知并提供身份证明，所有权证明，我们将在收到认证文件后删除相关内容。  
  
文中所涉及的技术、思路及工具等相关知识仅供安全为目的的学习使用，任何人不得将其应用于非法用途及盈利等目的，间接使用文章中的任何工具、思路及技术，我方对于由此引起的法律后果概不负责。  
## 🌟简介  
  
近日，安全人员发现并验证了一个存在于微信Windows客户端的安全漏洞，  
该漏洞由“目录穿越”漏洞链与“远程代码执行（RCE）”组合触发，攻击者可利用恶意文件在用户无感知的情况下远程执行任意代码。  
  
攻击者可以构造特殊的恶意文件，诱导用户通过微信接收并触发该文件。在用户毫无察觉的情况下，攻击者即可远程执行任意代码，并可能进一步实现对系统的控制或维持持久访问权限，严重威胁终端安全。  
  
漏洞的核心原因在于微信Windows客户端在处理聊天记录中文件的自动下载功能时，未对文件路径进行严格校验和过滤。  
  
具体攻击方式为：攻击者通过发送带有恶意构造文件的聊天消息，当用户在微信中查看相关聊天记录时，该文件将被自动下载并复制到系统的启动目录中。攻击者通过目录穿越技术绕过微信的安全防护机制，将恶意代码植入Windows系统的关键路径，从而实现开机自启动。  
  
一旦用户的计算机重启后，植入的恶意文件即被激活，攻击者便可远程受害主机，执行任意指令，对系统进行操控或长期驻留。  
  
影响版本  
  
微信Windows客户端3.9及更早版本均受到此漏洞影响。  
  
处置措施  
  
为保险起见建议请前往微信官网下载Windows版微信并覆盖旧版本。  
  
最新版本微信为  
4.0.6.21，确认更新至该版本即可。  
  
  
  
欢迎关注SecHub网络安全社区，SecHub网络安全社区目前邀请式注册，邀请码获取见公众号菜单【邀请码】  
  
**#**  
  
  
**企业简介**  
  
  
**赛克艾威 - 网络安全解决方案提供商**  
  
****  
       北京赛克艾威科技有限公司（简称：赛克艾威），成立于2016年9月，提供全面的安全解决方案和专业的技术服务，帮助客户保护数字资产和网络环境的安全。  
  
  
安全评估|渗透测试|漏洞扫描|安全巡检  
  
代码审计|钓鱼演练|应急响应|安全运维  
  
重大时刻安保|企业安全培训  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**联系方式**  
  
电话｜010-86460828   
  
官网｜https://sechub.com.cn  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0FW5uwU0BZtn2lmMrLPwpibCeCVbtBFDRkbFb7n7ibhPRxg20spUo9mUIiakmRYABB88Idl81IpGuXfw/640?wx_fmt=gif "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwyhlWCYDVqK38BA5dbjKkH7icWmAew7SYRA7ao1bFibialrMvmQ9ib0TBvw/640?wx_fmt=jpeg "")  
  
  
**公众号：**  
sechub安全  
  
**哔哩号：**  
SecHub官方账号  
  
  
  
