#  国家级黑客利用三大 Ivanti CSA 零日漏洞展开攻击，企业需警惕！   
原创 紫队  紫队安全研究   2024-11-20 03:59  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号现在只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8TtLmcLkFhzswbfPuJ9MR5nzZJCsia6WChciaZXjI2OIjp3H3bZTpwBPOvMKGsCGPEicLILI7BNmdMQQ/640?wx_fmt=png&from=appmsg "")  
  
在近期网络安全事件中，知名安全厂商Fortinet FortiGuard Labs研究团队警告称，一名疑似国家级黑客组织正在利用Ivanti Cloud Service Appliance（CSA）中的三大零日漏洞对企业网络实施恶意攻击。这次攻击不仅展示了黑客的技术水平，更凸显了网络安全防护的重要性。  
  
  
一、三大漏洞揭示了什么？  
  
1. CVE-2024-9380 - Ivanti CSA版本5.0.2之前的操作系统命令注入漏洞，CVSS评分7.2。攻击者需具备管理员权限，一旦成功，可远程执行代码。  
  
2. CVE-2024-8190 - 影响Ivanti CSA 4.6 Patch 518及之前版本的命令注入漏洞。此漏洞同样需要攻击者拥有管理员权限，以实现远程代码执行。  
  
3. CVE-2024-8963 - Ivanti CSA 4.6 Patch 519之前的路径遍历漏洞，CVSS评分9.4。此漏洞无需认证，攻击者可未经授权访问系统的敏感功能。  
  
  
二、黑客的攻击链条  
  
通过这些漏洞，黑客不仅能够获得CSA设备的未授权访问权限，还能枚举用户信息并试图获取凭据。攻击者利用所获得的管理员凭证在CSA设备上执行命令注入攻击，随后部署了名为“help.php”的Web shell（网络后门）。  
  
  
在获取访问权限后，黑客通过修改代码以“补丁”漏洞来封锁其它攻击者的入侵。此举表明攻击者试图确保独占的访问权限，进一步巩固对受害网络的控制。  
  
  
三、攻击工具及持续性  
  
研究表明，攻击者使用了ReverseSocks5代理工具来攻击内部网络，并试图部署Linux内核模块rootkit以确保持久性访问。即使系统恢复出厂设置，该rootkit仍有可能在系统中驻留，这加大了企业防御的难度。  
  
  
四、防护建议  
  
面对高超的攻击技巧和零日漏洞链攻击，企业应当采取有效的安全防护措施，尤其是及时更新补丁，并加强网络入侵监控。Ivanti公司和Fortinet建议用户定期检查系统日志，确保CSA设备上没有恶意脚本或后门，同时严格限制CSA设备的访问权限，防止未经授权的访问。  
  
  
结语  
  
本次Ivanti CSA漏洞攻击再次警示企业：网络攻击者技术不断提升，零日漏洞带来的风险不容小觑。企业需积极部署安全策略，确保网络和敏感数据的安全。  
  
****  
****  
**推荐阅读：知识星球连载创作"全球高级持续威胁：网络世界的隐形战争"，总共26章，相信能够为你带来不一样的世界认知，欢迎感兴趣的朋友****加入沟通交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png "")  
  
****  
**欢迎喜欢文章的朋友点赞、转发、赞赏，你的每一次鼓励，都是我继续前进的动力。**  
  
****  
  
  
  
