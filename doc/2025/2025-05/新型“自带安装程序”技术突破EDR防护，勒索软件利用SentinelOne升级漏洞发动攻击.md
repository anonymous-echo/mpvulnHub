#  新型“自带安装程序”技术突破EDR防护，勒索软件利用SentinelOne升级漏洞发动攻击   
网空闲话  网空闲话plus   2025-05-05 23:15  
  
网络安全公司Aon旗下的Stroz Friedberg团队于2025年5月5日披露，勒索团伙利用SentinelOne终端防护软件的代理升级流程漏洞，通过合法安装程序绕过防篡改机制并禁用EDR防护，成功部署Babuk勒索软件。攻击者通过获取目标网络管理权限后，运行SentinelOne安装程序触发代理升级流程，在旧版本代理服务终止、新版本尚未启动的短暂窗口期，强制终止安装进程，使设备处于无保护状态。此技术无需依赖第三方工具，直接滥用厂商原生安装程序，影响多个版本代理程序，即便最新版本亦未幸免。SentinelOne于2025年1月向客户推送缓解方案，要求启用“在线授权”功能（默认关闭），该功能需管理控制台审批后方可执行代理程序的安装、降级或卸载操作，从而阻断攻击链。然而调查显示，部分客户仍未启用该防护。目前该技术暂未影响Palo Alto等其他EDR厂商，但SentinelOne已向行业共享攻击细节以协同防御。此次事件暴露出EDR系统在软件更新机制中的设计缺陷，凸显供应链信任滥用风险，企业需强化权限管控并严格执行安全策略审批流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icUKBDCaFXMLUiahZMze81OjIicBKuD19sbEDVaRbY8Ta8WEHicGR8zKicZfBSmYfBefaoUsQ7raFt0dfQ/640?wx_fmt=webp&from=appmsg "")  
  
自带安装程序是一种技术，威胁行为者可以在配置不充分的情况下通过定时终止代理更新过程来绕过主机上的EDR保护。以下是Stroz Friedberg的技术报告。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icUKBDCaFXMLUiahZMze81OjIkOZydF1rgm7FhYuYicj1myiaAvLibibutlUwnSSaHZS3dw4CfBTrwichuGg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icUKBDCaFXMLUiahZMze81OjINLPYPBI60Rzmq3t1JQvqbSy3OzuEXSKxGI9J0sWsg696lEdP2ak61w/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icUKBDCaFXMLUiahZMze81OjIT2zZKt3FOuRO29xMWCoD3NPSPIDWPvP1YSy8dA6JuUX5rtBJUybuhw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icUKBDCaFXMLUiahZMze81OjIJxbqunqicv5J2LFVicTkGhB41wD9ARN6Cl6oLVSqTAeic8fZP6SLUicsHw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icUKBDCaFXMLUiahZMze81OjIJa1WWAPeBjbiasUubGXveLRibsFhRFx9C6fabPjzfGPdpbjcCdzIx3zA/640?wx_fmt=jpeg&from=appmsg "")  
  
【闲话简评】  
  
此次曝光的"自带安装程序"EDR绕过技术标志着勒索攻击战术的重大转折——从传统漏洞利用转向对安全产品原生机制的"信任劫持"。攻击者通过合法安装程序触发代理升级流程，精准利用毫秒级进程切换间隙实现防护瓦解，其核心在于将供应链信任转化为攻击武器。这种技术突破不仅使传统行为检测失效，更暴露EDR体系在"可信操作"盲区的致命缺陷：厂商预设的安装/升级流程成为攻击链关键环节，安全防线反成突破口。该战术的扩散可能引发连锁反应，如攻击成本降低，检测难度剧增，跨平台风险等。企业需重新评估"信任边界"，实施安装包哈希校验、升级进程行为基线监控等纵深防御措施，同时严格启用"在线授权"等审批控制。当安全产品自身成为攻击载体，被动依赖厂商方案已不足够，主动式零信任架构势在必行。  
  
参考资源  
  
1、  
https://www.aon.com/en/insights/cyber-labs/bring-your-own-installer-bypassing-sentinelone  
  
2、  
https://www.bleepingcomputer.com/news/security/new-bring-your-own-installer-edr-bypass-used-in-ransomware-attack/  
  
