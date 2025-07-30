#  “改密码就能防住？”全网疯传的Meta夺号案，撕开2FA致命漏洞   
勤奋的运营姐姐  EnhancerSec   2025-04-19 08:03  
  
## 第一章：破碎的友情  
  
小a颤抖着手指刷新手机屏幕，冷汗浸透了后背——她的Ins账号突然显示在异地登录，所有私人照片被替换成血腥恐怖图片，粉丝列表被清空，连与男友的甜蜜合照也变成了一行刺眼的红字：“这是你背叛的代价！”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnJZzlBgdiaCPdSoVoUGhbBeT6xyobiblsd2MwcA48Z1gB1V0UHh987xDLNsaQRzduI0TqvBaJLmWVHg/640?wx_fmt=png&from=appmsg "")  
  
她瞬间想起三天前与闺蜜小c的争吵。那天，她偶然发现小c偷偷向自己男友发送暧昧信息，盛怒之下将咖啡泼在对方脸上：“从今以后，我们不再是朋友！”小c冷笑离去时，眼中闪过一抹阴鸷的光。  
## 第二章：暗流涌动的“复仇计划”  
  
此刻的小c正蜷缩在网吧角落，屏幕光映出她扭曲的笑容。她早就知道小a所有社交账号共用同一组密码——毕竟当年是她亲手教这个“电脑白痴”设置的。  
  
“双因素验证？”她盯着Ins登录界面弹出的验证码提示，嗤笑着点开Facebook账户中心：“亲爱的，你难道不知道Meta的漏洞比我们的友情还脆弱吗？”  
## 第三章：行动开始  
  
小c在论坛上得知，攻击者可以从受害者 Facebook 或 Instagram 的帐户中⼼检索 Meta 2FA 备份代码以绕过 Meta 双因素身份验证（2FA）并获得对受害者 Meta 帐户的完全访问权限。 于是她开始了Meta 2FA 双因⼦绕过行动  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnJZzlBgdiaCPdSoVoUGhbBeTUoXFjyLqvWQgveTaGrqick3VzkGicdIGGAEKjF2KrXhnUibZIHjWUM5tw/640?wx_fmt=png&from=appmsg "")  
### Step 1：登录启动处理2FA  
1. 访问 Meta Auth。  
  
1. 使用受害者的 Facebook 或 Ins帐户登录。  
  
小c用旧密码轻松登录小a的Facebook账号，却在2FA验证卡壳。她果断点击“使用恢复代码”，指尖因兴奋而发抖。  
### Step 2：修改请求包  
1. 在浏览器中打开⼀个新选项卡，然后转到 Facebook 帐户中⼼双因素身份验证设置。  
  
1. 单击“其他⽅法”，然后单击“恢复代码”  
  
```
variables={"account_id":"victim_meta_account_id","account_type":"FRL","interface":"FB_WEB"}&doc_id=6358505927544740
```  
  
新标签页飞速跳转到Meta账户中心，小c在Burp Suite中截获FXAccountsCenterTwoFactorRecoveryCodesDialogQuery graphql   
数据宛如毒蛇露出獠牙——将account_id  
替换成小a的ID，doc_id  
修改为特定数值，整个过程比删除拉黑消息还要简单。  
### Step 3：代码检索  
1. 发送修改后的请求。  
  
1. 从响应中提取恢复代码。  
  
当系统返回的JSON数据中赫然陈列着10组恢复代码时，小c出尖锐的笑声。深夜的网吧里，无人注意到这个浑身颤抖的女孩正用沾着奶茶渍的键盘，将最后一串数字填入Instagram验证框。  
### Step 4：帐户接管  
1. 使用检索到的  2FA 备份代码登录受害者  Meta 帐户， 成功绕过2FA。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnJZzlBgdiaCPdSoVoUGhbBeTiblialCvdObpvQjWMMBk4zlSd6RiaKsF7nLia24Aib8YxUjsrv042gyqEkg/640?wx_fmt=png&from=appmsg "")  
  
凌晨三点，小a的账号彻底沦陷。小c疯狂上传伪造的出轨聊天记录，给共同好友群发诅咒信息，甚至用小a的口吻向品牌合作方发送辱骂邮件——她要让这个“虚伪的网红”社会性死亡。  
### 小插曲：漏洞成因  
  
存在该漏洞是因为 Facebook 帐户中心的Meta备份代码检索过程不需要 Instagram Meta 帐户密码。这种缺乏密码保护允许任何可以访问受害者 Facebook 帐户的⼈获得 Instagram Meta 备份代码，并绕过 2FA。相当于我知道了受害者的账号密码但是不知道他的 2FA ，⽽我通过⼀开始登录后可以去请求接⼝获取备份数据，以此获取到 了2FA 的 code ，就可以顺利进⼊到后台了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnJZzlBgdiaCPdSoVoUGhbBeTJHe9CZgqpmibgezpQ8VVaH22HxWWFPt24p6WuCbqKzg7kHfhnNpgWOg/640?wx_fmt=png&from=appmsg "")  
## 第四章：逆转的计时器  
  
“您有新的设备登录提醒。”小a突然收到Meta安全中心的邮件，定位地址竟是小c常去的网吧！她狂奔到警局，在网警报案时无意间点开公众号【EnhancerSec】的推文——《Meta 2FA惊天漏洞：你的恢复代码正在裸奔！》让她瞳孔骤缩。  
## 终章：代码背后的眼泪  
  
警方根据IP地址带走小c时，她正对着无法再登录的账号尖叫：“明明只要改个密码就能防住！为什么连漏洞都比你有良心？！”而在结案报道的评论区，一条高赞留言被顶到最前：“关注双因素验证安全，扫码加入QQ群，别让黑客偷走你的人生。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnJZzlBgdiaCPdSoVoUGhbBeTgSsWTLv6FRIkTlMYyC3gNqwKChX7PXkg7Lccf8T89Y3scxX41iajQzg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
