#  【漏洞预警】某华DSS系统存在命令执行漏洞   
原创 跟着斯叔唠安全  跟着斯叔唠安全   2025-05-16 00:01  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
资产测绘  
```
body:"/itc/include/script/My97DatePicker/WdatePicker.js"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9vRreILlC0XFUjjibgKbajchfDCEw9Qn4w4vrDVl7NeEQ1dnGkqmDXCQ/640?wx_fmt=png&from=appmsg "")  
  
  
2  
  
Action  
  
漏洞复现  
  
直接在命令执行点ping一下dnslog，顺便whoami一下看看当前权限。文末查看具体payload信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9KCLT1cicWria07S1aKhBOJaGD6JXVNJVG9iaT9pFD1rDAibVzz6DkVtXNw/640?wx_fmt=png&from=appmsg "")  
  
========================================================  
  
    逆向加解密算法，是渗透测试、漏洞挖掘中非常常见的场景。不少安全从业者都栽在了 Web、APP、小程序中的各种加解密逻辑上。要么绕不过去，要么耗时耗力搞不定，web加解密都要定位半天？  
  
为了解决这个问题，我们推出了这门课程：  
  
🎯 **《加解密逆向技能速成培训》**  
  
这是一门定位非常清晰的速成实战课。我们不教你写算法，我们教你如何“用好”算法。实战教学，如何用最高效的方式快速逆向加解密。  
## ✅ 课程定价  
  
仅需 **99 元**  
，一次性掌握  
Web/APP/小程序多端逆向技能。  
  
## 🎁 限时赠送内容（非常硬核）  
- ✅ 一年纷传圈子，专人答疑+资料分享  
  
- ✅ 魔改 Frida，能绕过市面绝大多数 Frida 检测  
  
- ✅ 小程序 RPC ，助力你打通小程序体系的算法逆向  
  
## 🧠 课程内容简介  
### 📌 加解密插件介绍  
- 快速接入主流插件，加快定位和分析速度  
  
### 📌 小程序加解密逆向  
- 如何定位加密逻辑  
  
- 使用 RPC 模块快速调试  
  
- 处理固定动态 key 的实际思路和案例  
  
### 📌 Web 加解密逆向  
- 手工 + 工具双路线，一键定位，绝杀加密  
  
- 搭配 RPC 框架高效完成 JSHook  
  
- 定位常见 Web 加密套路  
  
### 📌 APP 加解密逆向  
- 利用“算法自吐”技巧快速获取关键数据  
  
- 手工配合 RPC 脚本进行有效调试  
  
- 抓住动态 key + 多态混淆的实际处理技巧  
  
## 💬 课程定位说明  
  
这不是爬虫课程。我们不花大量时间去研究 AES、RSA、SM4等等算法是如何实现的。我们要做的是：  
  
✅ **把这些算法直接利用起来，为渗透服务**  
  
✅ **提升调试、hook、定位、利用能力**  
  
✅ **实现“实战优先”，“效率为王”，快速赋能**  
  
  
📩 **报名方式**  
：  
  
添加下方微信  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Uas6U1icvb8icYp1OrIE2u7V6mNruxrBiaapKt8RxumiaYGCHibbGA5uwU8tstHADxf77CbcjWcibXp4P8A/640?wx_fmt=png&from=appmsg "")  
  
  
3  
  
End  
  
🚀 **新圈子上线 | 高质量安全内容持续更新中！**  
  
我最近在纷传上建立了一个全新的安全技术圈子，主要聚焦于 **WEB安全、APP安全、代码审计、漏洞分享**  
 等核心方向。目前圈子刚刚建立，内容还不算多，但会**持续高频更新**  
，只分享真正有价值、有深度的干货文章。  
  
📚 圈子中包含：  
- 高质量原创或精选的安全技术文章  
  
- 公众号历史付费内容免费查看（如：小程序RPC、APP抓包解决方案）  
  
- 一些只在圈子内分享的独家思路和实战经验  
  
文章中涉及的完整POC及代码审计报告已上传至纷传圈子中，需要的师傅可以自取哈  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9gvdmBnX6lOnSygn4NFJlzqeyxyes0uIYicDwGwh3rbAYicdwYFhK3Ang/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
