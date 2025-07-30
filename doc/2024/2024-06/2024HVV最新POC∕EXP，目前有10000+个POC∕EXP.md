#  2024HVV最新POC/EXP，目前有10000+个POC/EXP   
原创 太白  仙网攻城狮   2024-06-29 20:46  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/P9wKrJiapDcwq3ESbCp9ZHpficoGfzgmKCzROWOJQwGLv3tkMjj81huo4VXibXJibibHDylYgIrw9NVtOJqqJvmjnKQ/640?wx_fmt=gif "")  
  
点击"  
仙网攻城狮”关注我们哦~  
  
不当想研发的渗透人不是好运维![](https://mmbiz.qpic.cn/mmbiz_png/moiaGhNkMybbibLUabCL7icBfTysKnlkLmk3yo3aANtTz4qQwkyT2iaLk5cbFv2xemz44FPveI2mNKdDk3lNruZwgA/640?wx_fmt=png "")  
  
  
让我们每天进步一点点  
  
  
**简介**  
  
都是网上收集的POC和EXP，最新收集时间是2024年五月，需要的自取。  
  
表里没有的可以翻翻之前的文章，资源比较零散没有整合起来。  
  
文件链接：  
  
https://pan.baidu.com/s/1PgJmgQFhl_7atGIkTaZyeQ  
  
提取码：6666  
  
其他资源失效了请给我留言  
  
![](https://mmbiz.qpic.cn/mmbiz_png/moiaGhNkMybaE6ia5mBe1ceGFZWvByzLliam0tDbQjnazdfKU5MTlCOuo9ovGjLxs7R9yUCkSmicrUarGr0Yib2UB5g/640?wx_fmt=png "")  
  
**实战**  
  
# CVE-2024-28995 Serv-U  
  
CVE-2024-37032   
开源  
AI  
模型  
 Ollama   
远程代码执行漏洞  
  
CVE-2024-29972 –
NsaRescueAngel  
后门账户  
CVE-2023-22515-**Atlassian
Confluence Data Center****权限管理不当**  
祝各位HVV顺利  
## 工作环境  
- 工作时全部操作均在虚拟机中完成  
  
- 虚拟机中不登陆个人账  
号，如QQ、微信、网盘、CSDN等  
  
- 渗透环境、开发环境、调试环境需要分开，从目标服务器上下载的程序需要在单独的环境中测试运行  
  
- 渗透虚拟机中全程使用代理IP上网  
  
- 物理机必须安装安全防护软件，并安装最新补丁，卸载与公司相关的特定软件  
  
- fofa、cmd5、天眼查等第三方工具平台  
账号密码不得与公司有关，云协作平台同理  
  
- RAT使用CDN保护的域名上线  
  
- 尽量不使用公司网络出口，可以使用移动4G网卡，然后虚拟机再链  
代理  
  
## 渗透工具  
- WebShell不能使用普通一句话木马，连接端使用加密流量，建议使用蚁剑  
  
- 不使用默认冰蝎，需要修改为硬编码密钥  
  
- 内网渗透时尽量使用socks代理，在本地操作  
  
- 上传程序到目标服务器时，需要修改文件名：如svchost等，尽量不上传内部自研工具  
  
- 公开工具需要去除特征指纹，如：sqlmap、masscan、Beacon证书  
  
- 工具需要设置线程或访问频率，如sqlmap的--delay、内网扫描时线程不大于5  
  
- Cobalt Strike后⻔上线后，设置time.sleep⼤于500秒  
  
- 手机短信验证码需使用在线平台如z-sms.com  
  
- socks代理通道需要使用SSL加密  
  
## 重点  
- 攻防演习成功的关键是团队协作，要互相帮助学习和进步，不要勾心斗角，每个团队的成功都需要有人当红花有人当绿叶的，外网打点与内网渗透同等重要  
  
- 渗透过程中，记住上传的webshell、木马等地址，服务器添加的账号  
，项目结束后要删除或描述在报告中，避免不必要的麻烦  
  
- 登陆3389不建议添加用户，尝试激活guest，如必须要添加  
账  
号，  
账  
号名与目标相关即可，避免使用qax、qaxNB等友商关键词  
  
- 清理日志时需要以文件覆盖的方式删除文件，防止数据恢复，或者仅删除指定ID的日志  
  
- 碰到蜜罐就不要慌，多喝点花茶，这样嘎了会比较香  
  
**往期内容**  
  
[2023HW-8月（10-15）53个0day,1day漏洞汇总含POC、EXP](http://mp.weixin.qq.com/s?__biz=Mzg2MjAyMTczMw==&mid=2247485600&idx=1&sn=5d99bcee1e4ab5a9fc7c95bb84e44b84&chksm=ce0f79aaf978f0bc6381a7e83c7d7cb1c5ef4252bd9049240436c3024888b54921d092b0b02e&scene=21#wechat_redirect)  
  
  
[Stable DiffusionAI绘画一键启动整合包](http://mp.weixin.qq.com/s?__biz=Mzg2MjAyMTczMw==&mid=2247485539&idx=1&sn=88531678bbde590d1a82bf0c6fc966f1&chksm=ce0f7969f978f07f2d81a99f50411860e0644435b348566e322ee72ea477d1b44c573b14b161&scene=21#wechat_redirect)  
  
  
[能让你躺着挖洞的BurpSuite插件](http://mp.weixin.qq.com/s?__biz=Mzg2MjAyMTczMw==&mid=2247485434&idx=1&sn=41cc795da91f4dba02d0f8aa54c62751&chksm=ce0f76f0f978ffe6a930ed0563fd05cc0114024b78abcb6a89f8a11fdea0b6c7e304d1803518&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/moiaGhNkMybbgSu3BUQQCwLOmp586w4lT8cjfictxv2UDdlgic4Dbpabk8nOm4B0vLDo3DlDdBoMukplXDUiaB5cicA/640?wx_fmt=gif "")  
  
更多资讯长按二维码 关注我们  
  
     
专业的信息安全团队，给你最安全的保障。定期推送黑客知识和网络安全知识文章，让各位了解黑客的世界，学习黑客知识，普及安全知识，提高安全意识。  
  
**觉得不错点个“赞”呗******  
  
