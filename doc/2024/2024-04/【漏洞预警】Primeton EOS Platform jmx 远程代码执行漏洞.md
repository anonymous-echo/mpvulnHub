#  【漏洞预警】Primeton EOS Platform jmx 远程代码执行漏洞   
cexlife  飓风网络安全   2024-04-25 17:34  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01fgpoFFHMYFurqV6A2yRmCV65bPwMDCMtYZ8HNHvwwvL62cch7WcaeY6D7OicTDrBxEjFtNBfhPLQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
  
Primeton EOS Platform是一款集成了开发运维一体化等功能的企业级应用开发平台,2024年4月,互联网上披露其存在反序列化代码执行漏洞,攻击者可构造恶意请求触发反序列化,执行任意代码,官方已经发布安全更新,建议升级修复,Primeton EOS Platform 7.6 及之前版本中存在反序列化漏洞,未授权的攻击者可向default/.remote接口发送包含恶意payload远程执行任意代码,官方已发布漏洞补丁,通过DeserializeCheckList对反序列化的类进行黑名单检查修复此漏洞。**影响范围:**Primeton EOS Platform ≤ 7.6**漏洞复现:**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01fgpoFFHMYFurqV6A2yRmCZJiavoQysaHta2CADzxNxGTNf1NqmHvOAyQlD08IxFEFO0AOrKoWic9w/640?wx_fmt=png&from=appmsg "")  
  
**利用条件:**1、用户认证:不需要用户认证2、前置条件:默认配置3、触发方式:远程**修复方案:**  
  
官方已发布补丁:https://doc.primeton.com:29091/pages/viewpage.action?pageId=118129732  
  
建议在确认不需要使用JMX功能情况下,屏蔽JMX请求,以减少潜在的安全风险,可参考官方修复方案删除相关的配置文件更新相关的漏洞补丁3RD SECURITY 20240125_C1、3RD COMMONS COLLECTIONS 3.2 20151223 P1PLATFORM_V7_SERVER 20230725_P1,补丁会拦截黑名单中列出的一些常见第三方开源类,这些类存在反序列化漏洞,当系统遇到这些类时,补丁将阻止其成功的反序列化,从而有效地防止潜在的攻击行为.  
  
  
