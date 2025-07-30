#  【代码审计】某安全数据交换系统的多个RCE漏洞挖掘   
倾旋  Z2O安全攻防   2023-10-09 20:30  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
> 分享一下挖掘某安全数据交换系统漏洞的过程。  
  
  
最初拿到的系统是一个vmware虚拟机，系统是Linux  
  
基本信息：  
- • 后台管理界面用户名密码：admin/nxg@LL99  
  
- • 操作系统：root / bo%Fn!71、uninxg / lx$zR9ce  
  
#### 配置网络  
  
根据产品安装文档环境搭建完毕后，手动设置IP地址和DNS：  
  
手工修改 /etc/resolv.conf  
  
修改 /etc/NetworkManager/NetworkManager.conf 文件，在main部分添加 “dns=none” 选项：  
  
网络IP地址配置文件在 /etc/sysconfig/network-scripts 文件夹下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRBFIiaWnfBz9ZnouqAyBCzsJzibN35ibW4UVwhPves8unls2X9Y8yYzyzw/640?wx_fmt=png "null")  
  
notion image  
  
我添加了两个网卡，其中一个用来供本机访问：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRQicziau4wkGePCfpPSQK9YsRv3qvWNuttUE4BHPRZ54ibFYxyPtBVkbibw/640?wx_fmt=png "null")  
  
notion image  
  
/etc/sysconfig/network-scripts/ifcfg-eth1-1  
  
观察启动命令行：  
  
/home/leagsoft/SafeDataExchange/Apache 是Tomcat的安装目录，webapps目录下是部署的应用源代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRZumrP2icgeaYGr9DIS06XKz9Gs4kp4icTUicCAJPmdLrWJB0z46OTtgtA/640?wx_fmt=png "null")  
  
notion image  
  
将war包通过ssh拷贝至本地就可以看到整个项目的源代码了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR2lUFnyp6gQJgRJIWA6wJZzkBE9jJXCA8qdiaH8taqV3fOiaVeaiagibOvg/640?wx_fmt=png "null")  
  
notion image  
#### 源代码解密  
  
将war包拷贝到本地通过idea打开，发现关键代码的实现都是空，连spring的控制器都是空，初步怀疑是被加密了，那么它是如何加密的呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRtUVSz6Lz8HOS6sE0UibgpLEOEJBSiagHbczvpAqIxkrpVia33xrquGsUg/640?wx_fmt=png "null")  
  
notion image  
  
既然网站可以正常跑起来，那么应该是运行时的某种技术手段实现，观察启动命令行：  
  
命令行中有一个javaagent引起了我的注意：  
  
将lib文件夹拷贝到项目中，观察jar包的结构：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRM218ZTJhhbibYK6HZIhkaO1PsBRsCoicpQMrqWPZHFPiawxw6Bpp6y6tA/640?wx_fmt=png "null")  
  
notion image  
  
看样子是调用了javassist实现了一种内存补丁技术，找到Agent的入口方法，看看它做了什么：  
  
跟进CoreAgent.premain：  
  
这里可以看到，它是先通过ECFileConfig初始化，然后解密读取Ini/ec.file  
  
跟进ECFileConfig.getConfig()：  
  
恰好我在服务器上找到了这个文件 ECFile.ini ：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRXSUyUK4CicBs6uL70UdVCYLMib3u1fC8XLgO35Rsic825utBGOvDJUTicQ/640?wx_fmt=png "null")  
  
notion image  
  
再看看AgentTransformer 的实现：  
  
AgentTransformer 重写了ClassFileTransformer的transform方法，将每一个class和密码放入JarDecryptor.doDecrypt进行解密，最终返回字节码。  
  
再来看看JarDecryptor.doDecrypt的实现：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRtibwicv7ibNMia63g8eAESiaRtaiadeliasQp49yIzwaCA8JwiafgibBXroXTnQ/640?wx_fmt=png "null")  
  
notion image  
  
通过readEncryptedFile 方法读取**META-INF/.classes/** 下的class文件进行解密。  
  
回到文件目录，在META-INF下发现了许多加密的class字节码文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRfq0cZk9AtrAQ4SdjnL2ScgvxZaPz66xho0mdqvauuCr0AetYgDeiabQ/640?wx_fmt=png "null")  
  
notion image  
  
这里我通过编写一个类，调用JarDecryptor.doDecrypt对全部class进行了解密：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR3xYgNrcLfRUKeKZpht8s0cxFRBC1sJdCPyfbxib0VzVYGtjzUBUOxibQ/640?wx_fmt=png "null")  
  
notion image  
  
跑一下Main方法就能将所有的加密class字节码文件还原，大功告成。  
####   
  
远程调试Tomcat  
  
修改Tomcat安装目录下bin/catalina.sh 文件，通过定义catalina的配置选项可以在tomcat启动时开启远程调试端口。  
  
修改文件：/home/leagsoft/SafeDataExchange/Apache/bin/catalina.sh  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR3QcPGLvsDqwOJicXa5NHFA17Z6nlmmAibXZ3y9g8wOhzicaVWjDZIfE8w/640?wx_fmt=png "null")  
  
notion image  
  
加入内容：  
  
然后重启tomcat就可以进行远程调试了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRu14WH3erwdUSziaQiafo7H8ho2acqlkMqZhGQk8SA6GOLibibsziaUnpknw/640?wx_fmt=png "null")  
  
notion image  
  
打开idea，将原本没有方法实现的class替换为已经解密的class，添加远程调试配置：  
  
这里我替换了：  
  
WEB-INF/classes/com/leagsoft/nxg/dlp/controller/FileTrackMarkMessageController.class  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRkvp7eIX5IdLL162ddgmpavYXZIBBxMJz4ic0owgIJpxyocdNaCENajA/640?wx_fmt=png "null")  
  
notion image  
  
添加一个调试配置，点击Edit Configurations：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRQOheHicMo95LnmgibSJ1h9u3py4ibDJ2oLl31l7LkG77vRXiaTa0KExV0A/640?wx_fmt=png "null")  
  
notion image  
  
点击添加按钮，新增一个Remote配置：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKREsr9pHlXLGPTTiciaB0bTdqjvNez6AB9Zusp772UbOfRHeN7jWct9ibVA/640?wx_fmt=png "null")  
  
notion image  
  
填入远程调试的IP地址和端口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR4XhpibHQXU77sWRgPEgrqKPex3FrUibs1XJvOBJY0wic4SmaMTMpBpl2A/640?wx_fmt=png "null")  
  
notion image  
  
然后在要调试的方法下断点，点击调试按钮，控制台会提示已经连接到目标JVM：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRe8OL9KtlfJp6DY2MtyFqqRZTeSJhXhXXTKoHLoyV15c1zMFg2qW10Q/640?wx_fmt=png "null")  
  
notion image  
  
当访问到对应的控制器，并且代码执行时，断点会生效：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRiaAVG7MJCS9L5ggUwMvXe5URQBpYicbTGWjjyj51jSIQgDW3t6kbICIw/640?wx_fmt=png "null")  
  
notion image  
  
通过观察调用栈、局部变量的值可以很方便的帮助我们进行输入输出的判断。  
####   
  
后台命令执行一  
  
通过审计发现FileTrackMarkMessageController.class中的getUploadFileID 方法调用了Runtime.getRuntime().exec 可能会存在命令执行漏洞。  
  
我们的输入点是request对象，它被传入了getMultiParamterMap方法，跟进查看：  
  
request 被传入了ServletFileUpload，看来是一个文件上传的数据包。  
  
构造一个文件上传的数据包发送过去调试看看：  
  
此时局部变量的值：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKRfJjsywr5Av9WSr9mS3AUs6icviblqCFuc8s9dqtvNCbYmQiaIhZ8G8PnQ/640?wx_fmt=png "null")  
  
notion image  
  
我发现文件名被带入了/bin/sh -c 意味着文件名也可以作为命令执行，由于前面有进行文件扩展名的获取解析，这个方法会取文件名的最后一个. 作为分割，把扩展名取得后拼接在最后面，最好的命令注入点是文件扩展名，最终我的payload如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR0qXB9zOtgFSBGSpbF6gKB1QUcwcqT65AuHvEicIdQp2UlKJNjsADMkQ/640?wx_fmt=png "null")  
  
notion image  
  
利用``和${IFS}替代空格 在shell中的特点，可以达到任意命令执行的目的，我还发现它的java服务是以root用户启动的，意味着获取这个命令执行的权限就是最高权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR54wpwLJE4aIDicNnZTK43fBElDQvG6YxUP2EuwKe7fgMZ17H8gvyTicA/640?wx_fmt=png "null")  
  
notion image  
#### 后台命令执行二  
  
com.leagsoft.uex.sysparam.controller.NoticeConfigController.class 中的testNoticeEmailAction方法存在命令注入，在调用JavaShellUtil.executeCommand方法时，将用户输入带入了bash脚本后面，但LeagUtil.filterCmdParams对输入的值进行了过滤替换，不过因为参数没有放入单引号中，可以使用; 对前面的脚本进行闭合，从而绕过限制执行任意命令。  
  
发送数据包：  
#### 思考  
  
这款产品使用了javassist的动态执行技术，但是java始终还是java，我们只需要hook或者针对它最上层的代码进行研究即可，于是我根据本次漏洞挖掘，编写了一个工具：  
Rvn0xsy/DumperAnalyze: 通过JavaAgent与Javassist技术对JVM加载的类对象进行动态插桩，可以做一些破解、加密验证的绕过等操作 (github.com)  
  
通过JavaAgent与Javassist技术对JVM加载的类对象进行动态插桩，可以做一些破解、加密验证的绕过等操作。  
```
https://payloads.online/archivers/2023/09/18/acc369fd-9310-4351-889c-457b12da9c25
author:倾旋
```  
  
****  
  
# 技术交流  
  
  
### 知识星球  
  
  
致力于红蓝对抗，实战攻防，星球不定时更新内外网攻防渗透技巧，以及最新学习研究成果等。常态化更新最新安全动态。专题更新奇技淫巧小Tips及实战案例。  
  
涉及方向包括Web渗透、免杀绕过、内网攻防、代码审计、应急响应、云安全。星球中已发布   
**550+**  
****安全资源，不定时更新  
未公开或者小范围公开的漏洞  
，并为星友提供了教程、工具、POC&EXP以及各种学习笔记等等。  
([点我了解详情](http://mp.weixin.qq.com/s?__biz=Mzg2ODYxMzY3OQ==&mid=2247502558&idx=1&sn=6510627a91776bced518fa5199f2e5af&chksm=ceab219ef9dca88849f8e230cf17caddc5c59b4ee3dd2e55950ee091d7c2a5ce107151709544&scene=21#wechat_redirect)  
  
)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR0D9Z9h9GEf8Hz3UoqmdhGWWwnfraa2qjEBYRGwf38KokdYib7VJLzLA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkXDeDqGmPLFSKgxKtHibKR8SUOZzajavWQvFRSNlVMPu3r4HFlbibkOx9mZtKBDMn3rBxDdqwxwJA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。**（QQ群可直接扫码添加）**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKubCcJREicLMkEHIMkCDkGbfwqdiaWZUJtQ8ZNbMVFNTh7JyHdg69vRN2tBVbicNBAIWdgPQfjHoDxVmw/640?wx_fmt=png "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“**  
**书籍****" 获取 网络安全相关经典书籍电子版pdf**  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
****  
点个【 在看 】，你最好看  
  
