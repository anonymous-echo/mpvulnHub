#  【漏洞复现】某平台-down-sql注入漏洞   
原创 南极熊  SCA御盾   2024-11-18 01:42  
  
关注SCA御盾共筑网络安全  
  
（文末见星球活动）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhQYYic9ynHLru6nghp1wxBiaCxJmZ6agdTichU2fcaK4UPp73Z0Ynqy3uiaLRKIexTRCIic5ByMZTVWpw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**SCA御盾实验室的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
  
**为了甄别不法分子或可疑人员，本圈子不接收任何微信未实名认证的人员。进入圈子后，会进行二次甄别。杜绝一切的网络安全事件发生！！！**  
  
****  
  
  
  
  
  
  
**01**  
  
**FOFA语法**  
  
  
>     -   
```
app="PC-PHPCMS"||app="PHPCMS演示站"
```  
  
  
  
  
  
**02**  
  
**近期发布**  
  
> ![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIiag68iaeibTXHv428Vj7Wu2x2U07jaaXzUJmsxr57Z0MX949fUI9NvcAjN8QsXRRywGdu9ZgulpW79A/640?wx_fmt=png&from=appmsg "")  
  
> ![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIiag68iaeibTXHv428Vj7Wu2x2rQYzEXRBPwQEQibL6EIm5p8fWZqiaQLEYic2BKGlcBfJFPL0e0MmHIeVw/640?wx_fmt=png&from=appmsg "")  
  
> ****  
> **poc详情付费见文末或发布在知识星球**  
>   
  
  
**03**  
  
**星球活动及星球福利**  
  
**永久活动：**  
1、通过群里老人进入星球的新人，只需79元进入，老人也会得到15元现金奖励。加入方式与奖励方式皆通过私聊，不支持退款2、星球开通分享有赏功能，通过老人分享的星球进入的新人，老人返现16元左右，新人返现10元左右  
  
3、通过私聊进入星球的，只需90元，但不支持退款  
  
  
三、星球福利  
  
1、工作日推送1day或0day、漏洞集合与技术文，期间不定期推送实用工具或脚本（大型节假日请假）  
  
2、补天半自动化交洞脚本已推出，价格10-50元视服务而定  
  
4、fofaweb（会员key包的web，可直接在线使用。不分享会员key）  
  
5、hunter充值8折优惠  
  
6、帮忙代导出hunter全量资产，具体进入星球后联系星主咨询  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RxxRc1KlrIiaUrr0LmPFc4XUP1yNkeSBPpqvbGibuUFianG0hjskaiaZ8Qugk0JIMlffvQX246HzDWO3UpnyKrVkOA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
**04**  
  
**poc详情**  
  
