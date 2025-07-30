> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTUzNzY3Ng==&mid=2247489173&idx=1&sn=3530ac4fe1631d177d454d6c931baebd

#  Kigen eSIM 漏洞导致数十亿物联网设备面临恶意攻击​风险  
 SecHub网络安全社区   2025-07-15 03:04  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZojCB4gjbFhVibLc60fIL38qR3kTBnnriaQQVUG8qV3vGWAnicE6SQUJ8WNiaq9OZp5u3tiag75C9sarHQ/640?wx_fmt=png&from=appmsg "")  
  
  
网络安全研究人员发现了一种新的黑客技术，**该技术利用了现代智能手机中使用的eSIM（嵌入式SIM）技术的弱点，将用户置于严重风险之中。**  
  
问题出在Kigen公司的eUICC（嵌入式通用集成电路卡）上。根据这家爱尔兰公司的网站数据，截至2020年12月，已有超过20亿张物联网设备SIM卡由其平台启用。  
  
该发现来自AG Security Research公司旗下的研究实验室Security Explorations。Kigen公司向该团队支付了30,000美元的漏洞赏金以感谢其报告。  
  
eSIM是一种数字SIM卡，它以软件形式直接嵌入到设备中的eUICC芯片上。eSIM允许用户无需物理SIM卡即可激活运营商的蜂窝网络套餐。eUICC软件提供了更改运营商配置文件、远程配置和管理SIM配置文件的能力。  
  
“eUICC卡使得将所谓的eSIM配置文件安装到目标芯片中成为可能，”Security Explorations解释道，“eSIM配置文件是移动订阅的软件表现形式。”  
  
根据Kigen发布的安全公告，**该漏洞源于GSMA TS.48通用测试配置文件（6.0及更早版本），该规范据称用于eSIM产品的无线电合规性测试。**  
  
具体而言，该缺陷允许安装未经验证且可能恶意的Java Card小程序（applet）。GSMA已于上月发布的TS.48 v7.0版本通过限制测试配置文件的使用来缓解此问题。该规范的所有其他版本均已被弃用。  
  
“成功利用此漏洞需要满足一系列特定条件的组合。攻击者必须首先获得目标eUICC的物理访问权限，并使用公开已知的密钥，”Kigen表示，“这使得攻击者能够安装恶意的JavaCard小程序。”  
  
此外，该漏洞还可能促成提取Kigen eUICC的身份证书，从而使得攻击者能够以明文形式下载移动网络运营商（MNO）的任意配置文件、访问MNO的机密信息、篡改配置文件并将其植入任意eUICC中，且不会被MNO标记。  
  
Security Explorations指出，此次发现建立在其2019年的研究基础上。该研究曾发现Oracle Java Card中存在多个安全漏洞，这些漏洞可能为在卡中部署持久性后门铺平道路。其中一个缺陷也影响了同样依赖Java Card技术的金雅拓（Gemalto）SIM卡。  
  
这些安全缺陷可被利用来“破坏底层Java Card虚拟机的内存安全”，获得对卡内存的完全访问权限，突破小程序防火墙，甚至可能实现本地代码执行。  
  
然而，Oracle当时淡化了潜在影响，并指出这些“安全隐患”并未影响其商用Java Card虚拟机生产版本。Security Explorations表示，如今这些“隐患”已被证明是“真实存在的漏洞”。  
  
**这些攻击手段听起来可能难以实施，但恰恰相反，它们完全在具备能力的国家级黑客组织的掌握范围之内。**  
攻击者可能借此入侵eSIM卡并部署隐蔽后门，有效拦截所有通信。  
  
“下载的配置文件可能被以某种方式修改，导致运营商完全失去对它的控制（无法远程控制/无法禁用作废等），运营商可能看到关于配置文件状态的完全虚假信息，或者其所有活动都可能被监控，”该公司补充道。  
  
“我们认为，仅通过攻破一个eUICC或窃取一份eUICC GSMA证书，就能窥探（明文下载）任意MNO的eSIM配置文件，这构成了eSIM架构的重大弱点。”  
  
****  
来源：  

```
https://thehackernews.com/2025/07/esim-vulnerability-in-kigens-euicc.html
```

  
  
  
  
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
  
  
  
