#  Mozilla紧急修复Firefox高危漏洞 与Chrome零日漏洞原理相似   
 FreeBuf   2025-03-28 19:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
在谷歌修复Chrome浏览器中一个已被积极利用的零日漏洞数日后，Mozilla也发布了针对Windows版Firefox浏览器高危安全漏洞的更新补丁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icjSGiba5s42zUByWyEMIW9qTYNs4ibUSy5o0wIYmyicMFAeXaKPbMCeEPLvicwicyd7gujQYsPKsxicueQ/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情与修复版本**  
  
  
  
该安全漏洞编号为CVE-2025-2857，被描述为"错误句柄导致沙箱逃逸"问题。Mozilla在公告中表示："在Chrome沙箱逃逸漏洞（CVE-2025-2783）曝光后，多位Firefox开发人员在我们浏览器的进程间通信（IPC）代码中发现了类似问题。"  
  
  
"受攻击的子进程可能导致父进程返回一个意外获得的高权限句柄，最终造成沙箱逃逸。"该漏洞影响Firefox及Firefox ESR（延长支持版），已在Firefox 136.0.4、Firefox ESR 115.21.1和Firefox ESR 128.8.1版本中修复。目前尚无证据表明CVE-2025-2857已被野外利用。  
  
  
**关联漏洞攻击事件**  
  
  
  
此次更新恰逢谷歌发布Chrome 134.0.6998.177/.178版本修复CVE-2025-2783漏洞。该漏洞已被用于针对俄罗斯媒体机构、教育单位和政府组织的攻击活动中。  
  
  
卡巴斯基（Kaspersky）在2025年3月中旬检测到相关攻击行为，受害者通过点击钓鱼邮件中的特制链接，使用Chrome浏览器访问攻击者控制的网站后遭到感染。  
  
  
**漏洞利用链分析**  
  
  
  
据分析，攻击者将CVE-2025-2783与浏览器中另一个未知漏洞串联使用，突破了沙箱限制实现远程代码执行。及时修补该漏洞可有效阻断整个攻击链条。  
  
  
美国网络安全和基础设施安全局（CISA）已将CVE-2025-2783列入已知被利用漏洞（KEV）目录，要求联邦机构在2025年4月17日前完成修复。建议所有用户及时更新浏览器至最新版本以防范潜在风险。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
