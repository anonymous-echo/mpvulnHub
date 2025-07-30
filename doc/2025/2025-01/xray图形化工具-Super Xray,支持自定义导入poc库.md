#  xray图形化工具-Super Xray,支持自定义导入poc库   
原创 track  泷羽Sec-track   2025-01-25 09:24  
  
>   
> 声明！本文章所有的工具分享仅仅只是供大家学习交流为主，切勿用于非法用途，如有任何触犯法律的行为，均与本人及团队无关！！！  
  
  
  
公众号回台回复**25125**  
即可获取  
  
[2024Goby红队版工具-附2024年poc合集，支持导入自定义poc库](https://mp.weixin.qq.com/s?__biz=MzkzNzg4MTI0NQ==&mid=2247485321&idx=1&sn=b3fd33cb785e9affc26dceaeec07c6b4&scene=21#wechat_redirect)  
  
  
[2024全年漏洞poc大合集及500份src报告](https://mp.weixin.qq.com/s?__biz=MzkzNzg4MTI0NQ==&mid=2247484688&idx=1&sn=94930f4a1b8f26b272e58042bfcb8594&scene=21#wechat_redirect)  
  
# Super Xray  
  
一款Web漏洞扫描工具**XRAY的GUI启动器**  
，xray是一款优秀的漏洞扫描工具，但目前只有命令行版本，通过 **config.yaml**  
 配置文件启动，很多情况下不好上手，需要一款 **GUI**  
 工具来帮助新人更快使用。  
  
项目源地址：  
```
https://github.com/4ra1n/super-xray

```  
## 环境准备及注意事项  
  
共有如下三种插件，使用方法也都说明了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9bWia7x9nNJYKCHFFBFlib335OMrtkeSeFsFBEofSGauWtz01ibFMnDiatg/640?wx_fmt=png&from=appmsg "")  
- 本地有 JRE/JDK 8+环境  
  
- 使用 **java -jar SuperXray.jar**  
启动(可以**双击**  
插件使用)  
  
- 需要事先下载**xray**  
  
**xray配置教程：2024web漏洞扫描辅助神器xray安装和使用**  
  
新版本内置了**一键下载**  
功能，点击这两处即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9iaIkxFLD0Ox2F0Xj1PibbVt6RRMcN9ia8RQ1iasogLh9pibLR3n36P7ianog/640?wx_fmt=png&from=appmsg "")  
  
image-20250125165841240  
### 注意事项  
- 请使用 1080P 及以上分辨率，在 720P 及以下分辨率可能无法完全显示  
  
- 请使用最新版xray（目前是1.9.4版本，本工具未兼容老版本xray）  
  
- 支持两种方式的exe文件，system版使用系统的JRE，另一种内置了JRE 8  
  
## 核心特性  
- **图形化界面，使用方便**  
  
- **内置多种poc，可自行导入**  
  
- **支持中英双语**  
  
- **内置多种插件，可自主选择**  
  
## 界面预览  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9JGZq4dz6ACqExgMIPrrYRcLv3MjaQIS2icOq5H7Olicf5yObAC2at02A/640?wx_fmt=png&from=appmsg "")  
  
初始界面  
## 在线生成poc  
  
点击此处即可跳转  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9hOb8kKle1pw6LdicKOx6lR18n64DutRtZ7y71At2x5qselWpR5ZfCJQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250125170450755  
  
然后在下面的界面**自定义poc**  
生成即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9dUxKq6YFKDFtjDJyOVGAbHqBpv2TUnaHNIwsoAX8EbK7D2aSmdWl3w/640?wx_fmt=png&from=appmsg "")  
  
image-20250125170424664  
## 指定多个PoC  
  
搜索后复制到输入框，注意换行分割  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9RJicGEz64lRBvfc6yw0UibKCDjVSMDW6XJq7svVaowwib3Z4cMAqibQd3g/640?wx_fmt=png&from=appmsg "")  
  
指定多个poc  
## 与rad联动  
  
在0.8版本以后可以与rad联动：  
  
注意：先输入端口开启被动扫描，再打开rad  
配合  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN98mVRP2NJ7kxa5U1W48vLzbxA2CqwYtI3RYaiaIjZp3oOCrhhN0O1odg/640?wx_fmt=png&from=appmsg "")  
  
rad  
## 子域名扫描  
  
在1.0版本以后支持子域名扫描，但是高级版才可以使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9zFxRslB5evzbs6dGHf9hH8ic1DviammmjiaxZtVRMEKRq5FxZwmeAqy5w/640?wx_fmt=png&from=appmsg "")  
## 反连平台  
1. 配置好客户端的反连平台后点击**配置服务端**  
  
1. 任意输入数据库文件名  
  
1. 任意输入token密码  
  
1. 不要改ip并输入一个监听端口  
  
1. 点击导出配置文件得到一个**reverse/config.yaml**  
  
1. 把xray  
和这个文件复制一份到服务端  
  
1. 服务端**./xray reverse**启动反连平台  
  
1. 在反连平台输入对应到**token**  
和**http url**  
即可（ip格式：http://127.0.0.1:80）  
  
1. 开启主动扫描或被动扫描即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9fictH91tfKPaQgAvE2M4XqOEoIic8VqGNdCNm4SY14rWQ9ZibHib7OZicjw/640?wx_fmt=png&from=appmsg "")  
  
image-20250125170048737  
## 服务扫描  
  
支持**Tomcat AJP**  
和一些**Weblogic IIOP**  
漏洞扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9MhqxdRdlTCKibrEaibyRb2gCkL7KJtSJpKFy7ibhVW4ceH6a7zYLjgnOg/640?wx_fmt=png&from=appmsg "")  
  
image-20250125170059728  
## 问题反馈及版本信息  
  
在界面左上角即可查看  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9LZ9m3Dun495XKnuvQvaXibUYcV216jf1Eoh1N7lDztv9Rib8qpSXICHw/640?wx_fmt=png&from=appmsg "")  
  
版本信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2o3r2zqqtwo7EQyTQ4fDN9qnc6hTjicQ0iaHrgsNzib44v6nweX3dya54qLjsHZ1ZiaC2ZI9yGichSPdA/640?wx_fmt=png&from=appmsg "")  
  
image-20250125170251787  
  
  
