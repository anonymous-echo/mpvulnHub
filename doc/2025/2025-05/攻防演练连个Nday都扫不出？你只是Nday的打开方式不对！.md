#  攻防演练连个Nday都扫不出？你只是Nday的打开方式不对！   
原创 跟着斯叔唠安全  跟着斯叔唠安全   2025-05-28 23:01  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
    众所周知，在一年接着一年的攻防演练加持下，再也回不到以前AWVS都能扫出来一堆漏洞的日子了。难道就一点Nday的活路都没有了吗？其实不然。  
  
2  
  
Action  
  
    经过最近几次的攻防演练总结下来发现，常规的Nday漏洞确实不太容易见到了，但凡露面超过三个月的漏洞，各甲方修复的嘎嘎勤快。但是例如编辑器之类的组件型Nday漏洞却时有发生。那么问题来了，为什么会出现这种情况呢？可能主要还是常规的Nday漏洞，漏洞路径固定且单一，甲方运维有个poc，nuclei一扫就能发现，即使运气好没被发现，打两次攻防演练，相关单位被通报两次也修复了，太容易被发现了。  
  
    但是组件型Nday漏洞，例如最广为人知的ueditor的aspx文件上传漏洞，虽然漏洞路径无非就是/ueditor/net/controller.ashx?action=catchimage&encode=utf-8（1.2.6版本后不是control，是imageup），但是它可能在根目录下，也可能在/js目录下，更可能在/lib，/script……各种个样的目录下。相比较而言，更加隐蔽，也就更容易成为漏网之鱼。  
  
  
    那么针对这种情况，我们该如何发现这些可能成为漏网之鱼的组件型Nday漏洞呢？在想清楚这个问题之前，我们先分析一下刚刚提到的这种组件型Nday漏洞的特征，因为存在的路径不固定，因此想要全面的发现它可能要涉及到爬虫技术，说到爬虫，我就想到了rad，但是rad单纯就是爬虫哇，没法加上一些漏扫的功能，如果有那么一款工具，又能爬虫，又能自定义poc，又能对爬虫到的路径去递归使用集成的poc，那就太完美了！  
  
    你还别说，还真有！在尝试了多款工具后，目光定格在了绿盟的EZ上。因为社区版的ez没有自集成这个ueditor漏洞，所以需要自己添加一下poc(有点太阉割了这么经典的漏洞都不集成)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZVovbZk0uItCptqWTInyBH505tuwTw8bypQMiadXJuLLlV1SMxXJ2b3FjWhODJUicWFxSUcOUZDbhQ/640?wx_fmt=png&from=appmsg "")  
  
    只需要在本地文件夹下新建一个pocs目录，然后创建ueditor漏洞的yaml文件即可。  
  
    在创建扫描任务参考如下  
```
./ez_darwin_arm64 webscan --crawler --uf url.txt --pocs ueditor
```  
  
    下面交给时间和狗运，即可收获一个不那么容易被发现的组件型Nday漏洞啦  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZVovbZk0uItCptqWTInyBHILKIK8jPic5dRCKdLyTJIePbqrhYHoB4RcOq75Of0BNZpc4Ohu2whsQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZVovbZk0uItCptqWTInyBHYyjEf6j3ibV74mdjqRo1gzoHrY0ib6BexPn3Ph964SXaUUK211tghtQw/640?wx_fmt=png&from=appmsg "")  
  
      
  
逆向加解密算法，是渗透测试、漏洞挖掘中非常常见的场景。不少安全从业者都栽在了 Web、APP、小程序中的各种加解密逻辑上。要么绕不过去，要么耗时耗力搞不定，web加解密都要定位半天？  
  
  
为了解决这个问题，我们推出了这门课程：  
  
🎯 《加解密逆向技能速成培训》  
  
这是一门定位非常清晰的速成实战课。我们不教你写算法，我们教你如何“用好”算法。实战教学，如何用最高效的方式快速逆向加解密。  
  
  
✅ 课程定价  
  
仅需 99 元，一次性掌握Web/APP/小程序多端逆向技能。  
  
  
🎁 限时赠送内容  
  
✅ 一年纷传圈子，专人答疑+资料分享  
  
✅ 小程序 RPC ，助力你打通小程序体系的算法逆向  
  
  
🧠 课程内容简介  
  
📌 加解密插件介绍  
  
快速接入主流插件，加快定位和分析速度  
  
📌 小程序加解密逆向  
  
如何定位加密逻辑  
  
使用 RPC 模块快速调试  
  
处理固定动态 key 的实际思路和案例  
  
📌 Web 加解密逆向  
  
手工 + 工具双路线，一键定位，绝杀加密  
  
搭配 RPC 框架高效完成 JSHook  
  
定位常见 Web 加密套路  
  
📌 APP 加解密逆向  
  
利用“算法自吐”技巧快速获取关键数据  
  
手工配合 RPC 脚本进行有效调试  
  
抓住动态 key + 多态混淆的实际处理技巧  
  
  
💬 课程定位说明  
  
这不是爬虫课程。我们不花大量时间去研究 AES、RSA、SM4等等算法是如何实现的。我们要做的是：  
  
✅ 把这些算法直接利用起来，为渗透服务  
  
✅ 提升调试、hook、定位、利用能力  
  
✅ 实现“实战优先”，“效率为王”，快速赋能  
  
  
记录一些师傅的学习反馈  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubmw9mujP6NBnUMiccj2sRe9G23NYSOp3f2THiacFibC5Q5iaFE2zp5GI35RgQOrt0YClh9qgpib0lF8hQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubmw9mujP6NBnUMiccj2sRe93e2u61sbQvvn31ufWH5nBicN8ejLSQLjB2CKriaPYp9UPYx3p8GZpxVQ/640?wx_fmt=png "")  
  
  
  
📩 报名方式：  
  
添加下方微信  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Uas6U1icvb8icYp1OrIE2u7V6mNruxrBiaapKt8RxumiaYGCHibbGA5uwU8tstHADxf77CbcjWcibXp4P8A/640?wx_fmt=png "")  
  
  
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
  
- 不定期分享0/1day  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9gvdmBnX6lOnSygn4NFJlzqeyxyes0uIYicDwGwh3rbAYicdwYFhK3Ang/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
