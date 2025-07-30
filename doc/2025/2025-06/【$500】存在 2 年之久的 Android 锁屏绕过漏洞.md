#  【$500】存在 2 年之久的 Android 锁屏绕过漏洞  
原创 骨哥说事  骨哥说事   2025-06-09 02:52  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4430  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
## 漏洞披露  
  
有多种方式可以从锁屏触发 APP 启动：  
- 利用DeepLink/BROWSABLE Intents（当按住选定文本并按下打开时）  
  
- 通过外部 USB 控制时，Gemini 应用将绕过 PIN 提示  
  
- Gboard 设置图标  
  
锁屏安卓设备实现步骤：  
1. 在 Gemini 中输入“https://discord.gg/a”  
  
1. 选中该文本并点击打开  
  
1. 搞定 :)  
  
## 漏洞影响  
  
泄露敏感信息（如果用户在锁屏上禁用了通知内容）的应用内容，如 Discord 消息，后被另一位研究员展示为允许从 Google Play 安装应用:  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jn8mazTnNXzTn1ORy1v99Qcic9x5UCHm4WTec1XmSaiaDbgCxV3ADuvUCTdz9fDJibwQa9TtYA5QuaXw/640?wx_fmt=png&from=appmsg "")  
  
file  
  
视频演示：  
https://www.youtube.com/watch?v=SmZsfn69B7E  
  
原文：https://ndevtk.github.io/writeups/2025/06/06/android-leak/  
  
- END -  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
