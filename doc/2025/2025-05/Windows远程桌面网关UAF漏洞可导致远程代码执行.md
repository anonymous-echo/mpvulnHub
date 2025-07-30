#  Windows远程桌面网关UAF漏洞可导致远程代码执行   
 FreeBuf   2025-05-19 10:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![Windows远程桌面网关漏洞示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOlTs9PicI6y5kfyrMUicr6NibUMbhfBOFBTLuOnHvn54QyIBnsic8hLjPfsuxlxYc35cyjX5sBxz1Tg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软远程桌面网关(RD Gateway)中存在一个高危漏洞，攻击者可利用该漏洞在受影响系统上远程执行恶意代码。该漏洞编号为CVE-2025-21297，由微软在2025年1月安全更新中披露，目前已在野外被积极利用。  
  
  
**Part01**  
### 漏洞技术分析  
  
  
该漏洞由昆仑实验室研究员VictorV发现并报告，属于远程桌面网关服务初始化过程中并发套接字连接触发的释放后重用(UAF)漏洞。具体而言，漏洞存在于aaedge.dll库的CTsgMsgServer::GetCTsgMsgServerInstance函数中，该函数在初始化全局指针(m_pMsgSvrInstance)时未进行适当的线程同步。  
  
  
安全公告解释称："当多个线程可以覆盖同一个全局指针时，就会触发该漏洞，导致引用计数损坏，最终引发悬垂指针解引用——这是典型的UAF场景。"这种竞态条件使攻击者能够利用内存分配和指针赋值不同步的时机问题，可能导致任意代码执行。微软为该漏洞分配的CVSS评分为8.1，属于高危级别。  
  
  
**Part02**  
### 漏洞利用条件  
  
  
研究人员指出，成功利用该漏洞需要攻击者完成以下步骤：  
  
  
1. 连接到运行RD Gateway角色的系统  
  
2. 通过多个套接字触发对RD Gateway的并发连接  
  
3. 利用内存分配和指针赋值不同步的时机问题  
  
4. 使一个连接在另一个连接完成引用前覆盖指针  
  
  
整个利用过程涉及线程间九步堆碰撞时间线，最终导致使用已释放的内存块，为任意代码执行打开大门。  
  
  
**Part03**  
### 受影响系统版本  
  
  
以下使用RD Gateway实现安全远程访问的Windows Server版本均受影响：  
  
- Windows Server 2016（核心版和标准版）  
  
- Windows Server 2019（核心版和标准版）  
  
- Windows Server 2022（核心版和标准版）  
  
- Windows Server 2025（核心版和标准版）  
  
将RD Gateway作为员工、承包商或合作伙伴远程办公关键接入点的组织面临特别风险。  
  
  
![远程桌面服务示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOlTs9PicI6y5kfyrMUicr6NXEQcFZAQEONjFVs9fibZmBHDmDiclP9ibkRc1ia8ic19WHch6WGyAXISKcw/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
**Part04**  
### 修复措施  
  
  
以下使用RD Gateway实现安全远程访问的Windows Server版本均受影响：  
  
  
微软在2025年5月补丁星期二通过引入基于互斥量的同步机制修复了该漏洞，确保任何时候只有一个线程可以初始化全局实例。以下是可用的安全更新：  
  
- Windows Server 2016：更新KB5050011  
  
- Windows Server 2019：更新KB5050008（版本10.0.17763.6775）  
  
- Windows Server 2022：更新KB5049983（版本10.0.20348.3091）  
  
- Windows Server 2025：更新KB5050009（版本10.0.26100.2894）  
  
安全专家强烈建议组织立即应用这些补丁。熟悉该问题的安全研究人员指出："对于依赖远程桌面网关实现安全远程访问的企业环境，该漏洞构成重大风险。"  
  
  
在应用补丁前，建议组织监控RD Gateway日志中的异常活动，并考虑实施网络级保护措施以限制来自可信源的入站连接。  
  
  
**参考来源：**  
  
Windows Remote Desktop Gateway UAF Vulnerability Allows Remote Code Execution  
  
https://cybersecuritynews.com/windows-remote-desktop-gateway-uaf-vulnerability/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320917&idx=3&sn=7dc05cb9d3ab151bf6da222ec282fb34&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
