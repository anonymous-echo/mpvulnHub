#  【安全圈】Ubuntu曝高危权限提升漏洞 三大绕过机制威胁Linux系统安全   
 安全圈   2025-04-01 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliafKqvJroMyht7kEelicQjic3m7y0pHY0FaqkO5QX66xVchGZMaLwLWe1SMGuaTB3ibr6VAJBzhxhu7A/640?wx_fmt=png&from=appmsg "")  
  
网络安全研究人员近期发现Ubuntu Linux系统存在三项严重安全缺陷，可允许本地攻击者绕过系统防护机制，利用内核漏洞提升权限。该漏洞主要影响Ubuntu 23.10和24.04 LTS版本中基于AppArmor的用户命名空间限制功能。  
  
三大核心技术绕过方式：  
1. aa-exec工具滥用 系统默认安装的aa-exec工具允许切换到宽松的AppArmor配置文件（如trinity、chrome等），攻击者可借此执行unshare命令创建无限制的命名空间，完全突破Ubuntu防护机制。  
  
1. Busybox利用 默认Busybox shell的AppArmor配置存在漏洞，攻击者可通过启动Busybox shell并执行特定命令，在服务器和桌面版系统上实现权限提升。  
  
1. LD_PRELOAD注入 通过向Nautilus（GNOME文件管理器）等可信进程注入恶意共享库，攻击者可以利用宽松的安全策略生成具备特权命名空间的shell环境。  
  
漏洞影响评估：  
- Ubuntu 24.04 LTS：默认开启防护机制但仍受影响  
  
- Ubuntu 23.10：需手动激活防护 虽然这些绕过方式本身不会直接导致系统沦陷，但会大幅降低利用内核内存损坏、竞态条件等漏洞的门槛，使本地攻击者获取root权限变得更为容易。  
  
官方应对措施： Canonical公司已确认这些限制属于纵深防御层面的缺陷，而非关键漏洞。建议管理员立即采取以下防护措施：  
1. 内核参数调优：   
  
通过设置kernel.apparmor_restrict_unprivileged_unconfined=1  
  
参数阻断aa-exec滥用  
  
1. 配置文件强化： 禁用Busybox和Nautilus的宽松AppArmor配置  
  
1. bwrap策略加强： 对依赖bwrap的应用程序（如Flatpak）实施细粒度命名空间控制  
  
  
安全建议： 企业用户可通过Qualys TruRisk Eliminate平台自动化部署防御措施，该平台提供：  
- 经过预测试的安全脚本  
  
- 与Qualys代理的集中管理集成  
  
- 关键资产的零补丁风险隔离方案  
  
行业专家指出，这一发现凸显了Linux发行版在易用性与安全性之间保持平衡的挑战。虽然Ubuntu的主动防护措施处于业界领先水平，但这些绕过技术也表明纵深防御机制可能意外引入新的攻击面。  
  
目前Canonical正与Qualys合作进行AppArmor的长期优化，预计将在未来版本中提供更完善的解决方案。在此之前，系统管理员需要及时手动应用缓解措施以保护易受攻击的系统。企业用户应特别关注内核级漏洞利用的增长趋势，将系统强化与实时威胁监测纳入安全运营的重点工作。  
  
来源：  
https://cybersecuritynews.com/ubuntu-security-bypasses/  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】注意！黑客利用 DNS MX 记录动态创建超 100 品牌虚假登录页面](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068822&idx=1&sn=8cba37c3dfd85ad34b512670c7a79919&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Triton RAT 利用 Telegram 远程访问和控制系统](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068822&idx=3&sn=ce96b1255407d26cc95c8b44d7d6c835&scene=21#wechat_redirect)  
  
  
  
[【安全圈】威胁通告：黑客组织利用WordPress MU插件目录隐匿恶意软件实现远程代码执行](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068822&idx=4&sn=77b1848c9bb8693ceed4d6eb03368eb5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】外包保洁员段某泄露3项国家机密！国安部披露细节：其为满足个人私欲，主动联系境外间谍情报机关](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068802&idx=1&sn=a972008459c14da64c552bc0c08183bb&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
