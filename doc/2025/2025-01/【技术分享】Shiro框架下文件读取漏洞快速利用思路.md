#  【技术分享】Shiro框架下文件读取漏洞快速利用思路   
原创 剁椒Muyou鱼头  剁椒Muyou鱼头   2025-01-01 01:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
**阅读须知**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
  
****  
**本公众号文章皆为网上公开的漏洞，仅供日常学习使用，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把**剁椒Muyou鱼头**  
“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD01hM2Bw8oTpcNCZl68Bj8T0aLpOHAMFCv9Qd6KeeQgTscOURdQUDbLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4Z7hc6oGV6C6IwibzfQUM1oq1yUciadAKQ3Ap29o8GGnBU52wXgSSicBxQ/640?wx_fmt=gif "")  
  
  
****  
**2025/01/01 星期三**  
  
**多云·东****北风1级**  
  
  
//01 Apache Shiro框架  
  
  
    Apache Shiro是一个强大且易用的Java安全框架，提供了身份验证、授权、加密和会话管理等功能，旨在帮助开发人员快速、轻松地实现应用程序的安全需求。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1gj0UPdpsBD91RpaOEqzZhNiaWAQhMIKyibzkbv4NhKrXTxGY0s4ME4D6K9aZzxtgnGxtD7xZRUUBA/640?wx_fmt=png&from=appmsg "")  
  
  
//02 Apache Shiro框架反序列化漏洞  
  
  
    在Java中，序列化是将对象转换为字节序列的过程，反序列化则是将字节序列恢复为对象的过程。Shiro在某些场景下（如“RememberMe”功能）会使用序列化来持久化用户相关的信息。Shiro默认使用了CookieRememberMeManager来处理“RememberMe”功能的cookie值。在Shiro<=1.2.4的版本中，AES加密的密钥是硬编码在代码里的，这导致了攻击者可以构造恶意数据来触发反序列化漏洞。而在1.2.4版本之后,ASE秘钥就没有默认了,需要获取到Key才可以进行利用。  
  
    攻击者构造恶意代码，并将其序列化、AES加密、Base64编码后，作为cookie的rememberMe字段发送。当Shiro接收到这个恶意的cookie并尝试反序列化其中的内容时，就会触发反序列化漏洞，允许攻击者执行任意代码。  
  
  
//03 Apache Shiro框架下文件读取漏洞  
  
  
    在日常渗透测试中，经常在Apache Shiro框架下获取JS中的接口或者FUZZ时发现任意文件读取/下载漏洞。但是在实际攻防演练时，文件读取漏洞并没有办法直接获取服务器权限，所以需要深度利用文件读取漏洞来进行进一步利用。  
  
    在某次测试系统时发现当前系统使用Apache Shiro框架搭建，但是并没有key进行利用，所以使用URLFinder工具爬取了系统JS中的所有接口，并放进BURP里进行批量测试，然后发现了/common/down?ljdz=这个接口存在报错。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1gj0UPdpsBD91RpaOEqzZhzibCOibeZvDibPN3vyDZzo1M0WB0zcnaUVwPHR3KNfUuSjGic1Lpj7NGEg/640?wx_fmt=png&from=appmsg "")  
  
  
    对当前接口进行测试，成功下载/etc/passwd文件，发现当前接口存在任意文件读取漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1gj0UPdpsBD91RpaOEqzZh0ibVZyUtMAPib9O1VwZyWkc7sa2fibFb4FicpichtBcNamiat5jziaXLfyGxQ/640?wx_fmt=png&from=appmsg "")  
  
      
  
    搜索了大量任意文件读取漏洞进一步的利用文章，在正常情况下，只需要尝试读取/var/lib/mlocate/mlocate.db文件，mlocate.db文件存储了当前服务器本地所有文件的配置信息，将他下载下来使用命令搜索或者为了省事可以直接Sublim Text打开，可能多需要点时间。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1gj0UPdpsBD91RpaOEqzZh3ZSoQHuPwKCqIcR62rQMAW2BKiciaVY3YSeUWib6I2ITibrIUT93V6Fmtw/640?wx_fmt=png&from=appmsg "")  
  
  
    打开mlocate.db文件后，需要搜索core关键词，尝试去寻找shiro-core-.jar包，然后根据搜索到的路径下载shiro-core-.jar包，将jar包进行反编译后搜索Base64.decode关键词尝试获取key进行反序列化漏洞的利用，从而执行命令获取服务器权限。快速搜索的话可以用以下工具，比较简单易用，照顾新手用户。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1gj0UPdpsBD91RpaOEqzZhQKOGoJibNzHMShQicVTGozx167LIs6yN2iaGuRnibzCBDmH5AsoLiav5rbg/640?wx_fmt=png&from=appmsg "")  
  
  
    简单总结一下最基础快速利用的步骤如下，当然这属于理想状态，实际渗透测试中会出现各种各样的问题。  
  
  
  
1.利用文件读取漏洞下载mlocate.db文件。  
  
2.下载后使用Sublim Text打开，搜索core相关的jar包。  
  
3.搜索到shiro-core.jar包，反编译后搜索关键词Base64.decode。  
  
4.利用获取到的key利用Shiro反序列化漏洞获取服务器权限。  
  
  
  
    如上所说，这属于理想状态下，际渗透测试中会出现各种各样的问题。可以搭配/root/.bash_history读取历史命令来进行辅助发现，在遗留的历史命令中，你可能碰到数据库用户名密码，也可能会碰到当前程序的jar包名字。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1gj0UPdpsBD91RpaOEqzZhbNadOgQgaHlh5GJlvGPUFLcmeaWaToE5oMQicnsagI4Ik5TDZXTlicHg/640?wx_fmt=png&from=appmsg "")  
  
  
  
    根据不同情况进行不同的利用方式，比如你获取到了数据库用户名密码，你可以尝试看一下互联网出口是否映射对应的数据库端口出来，从而进一步利用数据库权限进行提权。  
  
    或者你发现了程序的jar包，可以下载下载进行审计发现可利用的漏洞，也可以在下载mlocate.db文件后搜索不到core相关的jar包时，将当前程序的jar包下下来反编译后再次尝试搜索Base64.decode关键词来获取key。  
  
    在我有限的文件读取漏洞利用成功经验下，碰到过key藏在程序中但是搜索Base64.decode关键词时就是找不到，最后是搜索了==关键词最终找到了kay，从而进行利用获取了服务器权限。所以说还是得根据实际环境来随机应变，本文只是提供一个简单快速的思路，并不保证一定会成功。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1gj0UPdpsBD91RpaOEqzZhzzlWrnsH9hNJTsiaib4FXFYpSRNaS4iaXDCTA5huE234xAauBV3j7ttqg/640?wx_fmt=png&from=appmsg "")  
  
  
//04 总结  
  
  
    本文只讲述了Shiro框架下文件读取漏洞快速利用思路，实际渗透测试时，会碰到各种各样的文件读取下载漏洞，并不一定就是Shiro框架，所以各位朋友就当作一个简单的思路来看就好，实际环境下还是需要随机应变，当利用次数多了以后，可能拿到一个文件读取漏洞，就应该知道接下来该尝试读取什么进行深度利用了。  
  
    最后祝各位朋友，元旦快乐！  
  
  
  
    
END   
  
  
   
作者 | 剁椒Muyou鱼头  
   
  
I like you,but just like you.  
  
我喜欢你，仅仅如此，喜欢而已~  
  
  
  
  
**********点赞在看不迷路哦！**  
  
  
