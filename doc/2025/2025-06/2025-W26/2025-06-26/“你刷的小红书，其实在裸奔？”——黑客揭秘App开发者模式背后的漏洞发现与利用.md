> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4Nzk3MTg3MA==&mid=2247488427&idx=1&sn=9fc8ecfaa6360e9fbcf4ea5c4618a39d

#  “你刷的小红书，其实在裸奔？”——黑客揭秘App开发者模式背后的漏洞发现与利用  
原创 张飞  洞源实验室   2025-06-26 01:30  
  
    最近，一则“小红书内部开发者账号密码泄露”的消息在网上引起了热议。笔者作为一名重度的“小红书”成瘾者且又是长期从事网络安全研究的研究人员，里面对其问题进行了复现。虽然听起来像是“开发者操作失误”，但这背后其实藏着一种非常“质朴”的攻击方式——不仅仅是“密码泄露”这么简单。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPLRoPKIiaZu1nQFhetVOuphZpySgdoqiaHrl7yWnYMeg9ibO9m9xlgr9LA/640?wx_fmt=png&from=appmsg "")  
  
  
      和很多同行讨论的时候笔者心中也出现了一个疑问：这个入口到底还能深入利用到什么程度？，这个漏洞对于我们普通的"小红书"用户会带来什么影响，今天我就从“安全研究者”的角度，带大家还原整个事件，并分享一些攻击和利用的思路，哪怕你不是技术人员，也能看懂。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPnia3yuMkqUY2GJWzZtNhzZsQq8ch2vDspkF2gxHUBcWGd0fkz6kuQfg/640?wx_fmt=png&from=appmsg "")  
  
**01**  
  
漏洞背景回顾  
  
  
  
小红书开发者模式泄露事件发生于 2025 年 6 月 18 日晚。多位网友在技术社区 linux do、v2ex 等论坛贴出复现步骤，用户在小红书 app「设置」页标题处连续点按 6 次（部分说 10 次），随后在弹出的对话框中输入弱口令 xhsdev 即可进入隐藏的开发者模式，笔者也是第一时间去复现了该漏洞，分别使用小米的 Redmi K50 和 iPhone 13，点击设置按钮，发现只有 Android 系统下才存在该问题，这波 IOS 系统 + 1 分啊。  
  
  
  
  
从上述视频可以看到其中的很多调试信息，这些和开发相关的交互接口，作为一个开发人员或者安全人员该如何的利用呢？特别是作为渗透人员的笔者陷入了思考。  
  
   
  
  
**02**  
  
可能的深入利用思路  
  
  
1.网络层：抓包测试暴露的接口  
  
  
  
    笔者相信这也是大多数 Web 渗透人员第一时间想到的思路 —— 抓包找接口分析。可惜“小红书”团队响应太迅速了，这个漏洞目前已经被修复了，所以这边笔者找到了历史版本的小红书app（附录），弱口令虽然已经失效，但是调试的接口仍然开放着。可供测试   
  
    在分析 App 网络通信的过程中，一款顺手的抓包工具非常关键。笔者个人比较推荐 Proxyman，它不仅支持多平台，还能清晰地把各个 App 的数据流量分开展示，便于逐条分析、记录。  
  
接下来我们就用它来简单演示一下如何查看小红书 App 的请求数据包,经过笔者测试小红书 8.86.0 之前都是存在这个问题的 于是笔者对其使用Proxyman抓包进行监听。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPofwsKhU6vz2icrRNQxoLTk1dj5fxviaJibo8EZHuGnmQXPmiaDHIWct7Iw/640?wx_fmt=png&from=appmsg "")  
  
  
发现输入口令点击 “YES” 后，上述的请求没有增多，说明小红书的开发者口令可能是通过本地进行验证或者其他协议传输，致使我们的 Proxyman 无法识别其协议，也就无法抓取其数据包了。如果大概率是本地口令，那我们是否能根据弹窗追踪到其功能点呢？  
  
  
2.代码层：开发者模式的本地利用  
  
  
  
笔者开始以为类似小红书这种后门式的 “开发者模式” 是极小概率事件，点击 “设置” 7 下，输入 “xhsdev” 口令，才能进入的 “后门”，多么小的概率才能被一个白帽子完全猜对啊，所以才会有人说此次事件是有内部 “内鬼” 导致的安全事件。  
  
   
  
    后来和笔者车联网部门的同事谈起此事，他们说其实有许多的 app 都是存在这种开发者模式的，只是不清楚登录密码，比如 bilibili 旗下的 “必剪” app 连续点版本号 7-8 下，比如 “雷石 KTV” 等 app，找到 “版本号” 等系统配置信息轻点 7-8 下一般都能唤醒 “开发者模式” 的后门。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDP06a0xk11uJBwrtQhUwwyVEgRcXJSV08qQja3RXawDiaxLJUVINLzAbw/640?wx_fmt=png&from=appmsg "")  
  
必剪” app 开发者模式和 雷石 KTVapp 开发者模式截图  
  
  
为什么这么多 app 都会存在这些隐藏式的开发者模式？为了搞清楚这些 “后门” 的成因，笔者找了一个专供于 IoT Security、Mobile Security、Cloud security、Web Security 等人员学习研究的开源 app 项目。该 app 的所有行为、配置、接口都默认开启调试权限，虽然这个项目已经是 10 年前的，但现在仍然在支撑和维护中，项目地址（见附录）。该项目没有网络云端，只有本地端，正好通过学习这个 app 的测试方法去研究上述众多存在 “后门” 的 app。配置好 Android studio，直接导入项目源码，编译成 apk 就可以上手测试了。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPSSOdDRicHpWicL0pCFLiasmXE4tqZzeHLEiaicdXGNW441ZIFufCPBE9eDg/640?wx_fmt=png&from=appmsg "")  
  
  
笔者将编译好的 diva.apk 通过 adb 工具以及 Pixel2XL 手机连接并安装。  
  
    打开软件随便进行一项操作，输入 “key”，该 app 显示 Access denied，很明显该 key 是错误的。已知该 app 没有网络连接，所有的数据都是本地存储，那么该如何做呢？  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPAG7kScr67TPz7XGjQWgOSzBMibaR8T0hM8ItGV2VOK2YlSIrRu62WIw/640?wx_fmt=png&from=appmsg "")  
  
  
肯定是需要对本地apk的代码进行审计的。  
  
  
第一步： 查壳  
  
方式一：比较简单：使用国内的比较有名的查壳工具：PKID（限制为比较识别国内的壳）下载地址(见附录)  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPG4NTBTbic9U9ArQOI48Kjl7s6nGLG1Nfp6zmqIX7k0DToq84icHw4xUA/640?wx_fmt=png&from=appmsg "")  
  
  
方式二：比较复杂：使用frida-server+本地frida +查壳脚本（能适配几乎所有已知的壳）笔者使用工具AYA(下载地址见附录)  
  
使用frida-server 启动  
  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDP3J5qdRAYBXJcwN3HU3aebkKooybmic8FdBx9PwFda4bNicR5xpgMeSyg/640?wx_fmt=png&from=appmsg "")  
  
  
在手机中搭建好服务端后，输入命令：  
  
 frida -U -f jakhar.aseem.diva -l check_shellcode.js  
  
（注：  
jakhar.aseem.diva是apk包名   
check_shellcode.js查壳脚本  
见附录  
）  
  
进行查壳操作，此时 app 会自动启动一次。这表明该 frida 脚本会动态地从 apk 的 resource 目录下的 lib 文件夹中寻找带有壳的.so 文件。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPbmp4ubJXaM5p5bibzvn4RK9E8PABfrKFsbOib76QzjZtibyqe7oWE67RA/640?wx_fmt=png&from=appmsg "")  
  
  
通过上述方式我们未发现 Diva app 带壳。  
  
第二步：逆向和本地调试  
  
使用 jadx - gui 工具反编译该 Diva.apk，发现该代码是没有进行混淆的。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDP0xk4QuAvibmdaogr59IMahXibVp0quMVFSWCFkcibYfrXUt7qdOJuGRrw/640?wx_fmt=png&from=appmsg "")  
  
  
发现有关键字“Enter the vendor key"  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDP9BCyqt1lRyduIsmibCsjoFbM9jIbyhNEjwHtC1Vm5kniaDPDlxq66MfQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过不断的寻找终于找到该key的校验函数的出处  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPtGVSMeLwaCDwXuvSE8cORCtqADm1j7zbqP88vohvpJsrdgXchVlaXw/640?wx_fmt=png&from=appmsg "")  
  
  
最后找到   
  
hckey.getText().toString().equals("vendorsecretkey") 的匹配值  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPNlibENzAuhvTnK76auria1V2KibnYichQLJhVIasROwCXNDNVO5T8JfzsQ/640?wx_fmt=png&from=appmsg "")  
  
  
发现这个 key 确实可以 pass 这道题。  
  
带着刚学来的 “三板斧”，趁热笔者打开了上述所有存在 “开发者模式” 的 apk，对其进行查壳。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gEGSydvbZs5pmrm1efaXFztftuFqSpDP09tx8jzCEsgTFy4F3tibpydD8sL7ZAiaibNmz5BjeYBEibRLNic6slNbzcA/640?wx_fmt=gif&from=appmsg "")  
  
 1 小红书 apk(存在开发者模式)  
  
使用PKID检查是否有加壳  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPequcf8Xr8t4eBFRjfSVgLQZomRmyiaqxgp6Otzs4hmBDrPB8Jnwz44w/640?wx_fmt=png&from=appmsg "")  
  
  
使用 jadx-gui打开其apk，查看其代码  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPlqUibmv2v0SpYfXmwx8o2eh1icniaKfNNV5FMuP7SYibtHP0fWRvzoB2aw/640?wx_fmt=png&from=appmsg "")  
  
  
小红书做了很严格的混淆，还是从最开始的前端布局开始找找过去。这边使用的是 AYA ADB 调试工具 (见附录  
)。简直太好用了。可以看到 “YES” 和 "NO" 对应的是 //  
[@resource-id="android:id/button1"]   
和  
  
 //  
[@resource-id="android:id/button2"] 。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPezgWBUm4r0wA1fmTGSzOYgykcb8ULbpLbPPlwCByTJ5ib1se4Tu6c0Q/640?wx_fmt=png&from=appmsg "")  
  
  
笔者搜索了button1  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPelc0ZDJdwXuJ1MIBZib5NiaCxTlRkOTvLSuIeZticVx1mLuc3ibLy1rl1Q/640?wx_fmt=png&from=appmsg "")  
  
  
进行下一步  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPqWgwf2ZIAGvgX5kJ2A0EXKWMTSK7qSf4WkT9otKJQf5Du2HKGPzcKQ/640?wx_fmt=png&from=appmsg "")  
  
下一步  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPxsdribP5T6EI5ahIYicRQprD0oXDez8GlDA3R30oIg4Y9fEGIhsTNKlw/640?wx_fmt=png&from=appmsg "")  
  
  
这个方法好像是将两个 button 按钮进行绑定，也就是说，当点击 “YES” 或者 “NO” 的时候都会相当于点击小红书上的另一个存在的按钮。  
  
  
继续解析 "l"类的"f"方法  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPfpUQexkaWYYiaZiccvibbz0FwSEpyuF4LuepuTJ5cSNE4KbPV5GhshQhg/640?wx_fmt=png&from=appmsg "")  
  
  
该函数好像是用于动态替换方法的执行逻辑，可能是为了加固、动态注入代码或为了防止反向工程。然后继续往下找，好像找不到有趣的东西，于是笔者把几个相关类以及引用的类和引用这些方法的类看了一下，结果，笔者发现了本次的罪魁祸首 ——“xhsdev”。有没有可能并没有 “内鬼”，而是通过这种方式可以找到 “开发者模式” 的弱口令。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPMqicvmLssznK9QJZ2AqrpWZiauMMMh3ibJG7uyMiaSFgMiaa9ZUbpAOMJlA/640?wx_fmt=png&from=appmsg "")  
  
  
当笔者输入"xhsdev" 到存在"后门"的小红书的app时候，笔者发现  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPoVp2yWB5vzZAXYFqMIKcNOUjsE9UajfTwtc4Obzcr6KcVZ2CG1HyFw/640?wx_fmt=png&from=appmsg "")  
  
  
虽然加载失败，但是小红书的设置页面多了一个 “开发者模式” 的按钮，说明这个口令可以对这个app让其产生变化的，于是笔者想多找几个弱口令，是否能找到新 “口令”。  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPMB7DfU5wdaGTqzMJ7LR4EL2SgQFicRqqC8PeW44GwO8KtPEEuEmicmVQ/640?wx_fmt=png&from=appmsg "")  
  
  
笔者又发现了几个密码，将每一个都输入到调试窗口，然后记录app的变化：  
  
  
xhs_capa_draft：输入后点击‘YES’，跳转到隐私设置  
  
xhs_wk_cache_pass：没有反应  
  
xhs_common_demotion_cache_page: 没有反应  
  
xhs_dedup_cache_key：没有反应  
  
xhs_remove_repeat_page ：没有反应  
  
  
不存在该按钮或者被隐藏的都不跳转，也就是没有反应，而 xhs_capa_draft 口令能跳转至隐私设置，这也佐证了笔者基于前面代码的猜测（输入口令就会自动跳转到另一个存在的按钮，如果不存在就会没有反应），所以此次小红书的开发者口令校验真的很有可能就是写在本地的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gEGSydvbZs5pmrm1efaXFztftuFqSpDP09tx8jzCEsgTFy4F3tibpydD8sL7ZAiaibNmz5BjeYBEibRLNic6slNbzcA/640?wx_fmt=gif&from=appmsg "")  
  
2 雷石KTV（注：开发者模式 app 必须装载到车机上， apk下载见附录）  
  
查壳 ：没有发现壳  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPrxBxLxYuC6vV8Vtm395nTKDDCTicjRzW3icCicZ3ibnhOLEIicaSFJ7DjDQ/640?wx_fmt=png&from=appmsg "")  
  
  
反编译其apk 一秒钟得到其开发者模式的弱口令  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPOSh6XEtsVsiaPTqamOvagEqVibsCsqAAQyPRupvK0yDkR0bMTOtFibayg/640?wx_fmt=png&from=appmsg "")  
  
  
以下是笔者通过“666”登录车机开发者模式的视频  
  
  
  
  
笔者的目前只能想到这些，后面如果有新的思路，还会继续分享的，以下是笔者对存在该类型问题的app厂商的一些建议。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPnia3yuMkqUY2GJWzZtNhzZsQq8ch2vDspkF2gxHUBcWGd0fkz6kuQfg/640?wx_fmt=png&from=appmsg "")  
  
  
**03**  
  
防范与应对措施  
  
  
1.禁用线上版本的开发者模式  
  
  
  
    按照开发流程，或者说软件的生命周期中，开发者测试一般会在测试阶段或者最后的冒烟测试阶段，肯定不能进入生产环境也就是发布阶段的，做法也非常简单，在SDL流程中加入对app进行管控：  
  
    使用构建变量或编译标识（如 
```
BuildConfig.DEBUG
```

  
）控制是否启用开发者功能，如果启用卡点，打回开发流程或者测试流程  
  
2.严禁将账号密码硬编码或存储在本地  
  
  
  
    此次事件很大可能性就是，白帽子在进行漏洞挖掘的时候，正好测试到了其开发模式的触发点，然后通过笔者上述方式拿到的“口令”，所以本地化的弱口令才是罪魁祸首，所以尽量不要将账号密码、Token 等凭证硬编码或存储于 SQLite、明文文件中，极易被逆向提取的。  
  
    解决方式：不在客户端存储开发账号密码，或者使用使用动态凭证；  
  
对于确实需要本地持久化的敏感信息，应使用 Android Keystore + 加密算法（如 AES+RSA）加密处理，让其即使逆向也很难读取口令。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs5pmrm1efaXFztftuFqSpDPnia3yuMkqUY2GJWzZtNhzZsQq8ch2vDspkF2gxHUBcWGd0fkz6kuQfg/640?wx_fmt=png&from=appmsg "")  
  
附录  
  
  
小红书历史版本：https://www.wandoujia.com/apps/6233739/history  
  
DIVA项目：https://github.com/payatu/diva-android  
  
DIVA 下载:https://wwhh.lanzoul.com/iarYG2zjffmj 密码:51dm  
  
PKID下载地址：https://wwhh.lanzoul.com/iMWaZ2zjfvib 密码:enbq  
  
AYA下载地址：https://github.com/liriliri/aya   
  
雷石KTV APK下载地址：  
https://wwhh.lanzoul.com/iMRAA2zkdpri  
   
密码:  
9zqt  
  
