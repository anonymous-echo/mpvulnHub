#  紧急！朝鲜Kimsuky组织利用BlueKeep漏洞，疯狂攻击日韩！   
原创 紫队  紫队安全研究   2025-05-01 04:00  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SCmOpsuH4wtmWCI3rzpqoMX5UHXBlxPaJmiaHibQdciaSdCfvHdDiavDHdaYMGGuhIuFTYFADwFoicBIg/640?wx_fmt=png&from=appmsg "")  
  
网络安全的警报再次拉响！近日，一个令人脊背发凉的消息传来：与朝鲜相关的Kimsuky组织，正发起新一轮恶意攻击，利用早已被修复的微软远程桌面服务漏洞，试图撕开日韩网络防线！  
  
  
韩国AhnLab安全情报中心（ASEC）的研究人员在调查一起安全漏洞事件时，意外揪出了Kimsuky组织的恶行，并将此次行动命名为“Larva - 24005”。研究发现，攻击者竟然盯上了RDP（远程桌面协议）漏洞，企图借此打开目标系统的大门！  
  
  
ASEC发布的报告中提到：“在部分系统中，攻击者疑似利用RDP漏洞（BlueKeep，CVE-2019-0708）获取初始访问权限。虽然在被入侵系统中发现了RDP漏洞扫描器，但目前尚未找到实际利用该漏洞的证据。”原来，这群狡猾的攻击者还“多管齐下”，通过电子邮件夹带恶意文件，甚至利用微软Office公式编辑器漏洞（CVE-2017-11882）来传播恶意软件，简直防不胜防！  
  
  
一旦成功潜入系统，他们便开始疯狂“搞破坏”——安装MySpy恶意软件和RDPWrap，篡改系统配置，就是为了牢牢把控远程访问权限，把目标系统变成自己的“囊中之物”。到了攻击的最后阶段，更是祭出大杀器，部署KimaLogger或RandomQuery键盘记录器，偷偷记录用户的每一次按键操作，试图窃取各类敏感信息！更过分的是，研究人员还发现Kimsuky从被攻陷的系统中，向韩国和日本发送大量钓鱼邮件，恶意满满！  
  
  
其实，自2023年9月起，Kimsuky这个“网络毒瘤”就已经开始在全球范围内“兴风作浪”，目标直指韩国、美国、中国、日本、德国、新加坡等多个国家的机构。从2023年10月开始，韩国的软件、能源和金融等关键行业更是深受其害，持续遭到攻击。此次，ASEC的研究人员也公布了此次攻击的入侵指标（IoC），希望能帮助更多机构及时防范。  
  
  
Kimsuky这个网络间谍组织，还有ARCHIPELAGO、Black Banshee、Thallium等一堆“马甲”，早在2013年就被卡巴斯基的研究人员发现，背后受朝鲜侦察总局（RGB）的操控。2020年10月底，美国计算机应急响应小组（US-CERT）还专门发布报告，揭露了他们的攻击手法和基础设施。一直以来，这个组织就爱盯着韩国的智库等机构下手，同时也没放过美国、欧洲和俄罗斯等地的目标。  
  
  
今年2月，ASEC的研究人员就发现Kimsuky发动过鱼叉式网络钓鱼攻击。他们发送伪装成Office文档的恶意*.LNK快捷方式文件，一旦用户不小心点开，就会触发PowerShell或Mshta下载PebbleDash和RDP Wrapper等恶意软件，进而控制受感染系统。更可恶的是，他们还会使用特制的RDP Wrapper来开启远程桌面访问，甚至修改导出函数，就是为了躲避检测。不仅如此，还安装代理恶意软件，试图穿透内网，获取对受感染系统的外部访问权限，简直无所不用其极！  
  
  
Kimsuky组织使用的键盘记录器也是花样百出，涵盖多种文件格式，甚至还有PowerShell脚本。他们借助forceCopy窃取器恶意软件，疯狂捕获用户按键信息，还偷偷提取浏览器目录下的文件，隐私在他们面前仿佛“裸奔”！  
  
  
在这个网络威胁无处不在的时代，无论是企业还是个人，都必须提高警惕！及时更新系统补丁、安装可靠的安全防护软件、不随意点击不明邮件和链接……这些看似简单的操作，可能就是保护我们网络安全的关键！转发提醒身边的人，一起筑牢网络安全防线，别让Kimsuky这样的恶意组织有机可乘！   
  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
