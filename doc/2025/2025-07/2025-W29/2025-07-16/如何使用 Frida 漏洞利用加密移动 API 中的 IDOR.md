> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247497892&idx=1&sn=a1df282edd7c66180e2301060336e771

#  如何使用 Frida 漏洞利用加密移动 API 中的 IDOR  
 迪哥讲事   2025-07-15 12:51  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！请在授权的站点测试，遵守网络安全法！  
**仅供**  
**学习使用，****如若非法他用，与平台和本文作者无关，需自行负责！**  
  
  
我写这篇博客是为了分享我最近在Android应用程序渗透测试中的经验。我偶然发现了一个可以显示用户银行卡信息的应用程序。  
> 使用的工具“Jadx-GUI、Frida、Burp-Suite”  
  
  
在对 Android 应用程序进行动态测试时，我遇到了一个 API 调用，它的请求体和响应体都是加密的。由于整个应用程序的 API 调用都是非加密的，所以这看起来很奇怪。然而，这也很合理，因为该 API 调用可能包含卡信息（该 API 调用以  
**showCard**  
结尾）。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusPT2ReiaBtrWwrAxHDrdxlxnr2cyDJSNvBdAAlg4tibJSmJmEloECibo1A/640?wx_fmt=png&from=appmsg "")  
  
现在是时候找出 API 调用传递了哪些数据，以及它从服务器获取了哪些数据。为此，我需要进行一些静态代码分析。我向 Jadx-GUI 寻求帮助。在 Jadx、我的小脑袋和大量咖啡因的帮助下，我找到了  
**One Piece**  
（代码）。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuuslfd2gnXImxJGN95ibqGFQfGmnzNXkBaTxB1ONDntoqvChB00WX2QCbg/640?wx_fmt=png&from=appmsg "")  
  
加密背后的罪魁祸首  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusdRWUoq8G3PCx9Gg24vf7BiaZuMjptv8gPKPXvgPO5eDx1PsCkpM8Auw/640?wx_fmt=png&from=appmsg "")  
  
解密背后的罪魁祸首  
  
从这两段代码中，我了解到“   
**JSON ”值分别从函数“**  
  
**getJsonEncryptedValues()**  
和“   
**getDecryptedJsonValues() ”**  
传入和传出。我们可以使用 Frida 查看加密前后的这些值。现在是时候用 Frida 脚本来施展魔法了。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusHHeGsWOn2DlDicXfOvib7GJ4U5NgotXHdFSyj44Iyp67SiaemfWgP3MHA/640?wx_fmt=png&from=appmsg "")  
  
哒哒….！  
  
请求/响应主体解密的代码就在这里。是时候揭开开发者的秘密了。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusicdlL1wKJRfq0u2ZgFEAsd6hIUbGOgtO5iaLKYF8JmAiaV2bz2AEE37ng/640?wx_fmt=png&from=appmsg "")  
  
秘密就是秘密。  
  
在请求主体中，我发现了一个参数（“   
**mobileNumber”**  
），可以尝试IDOR，但加密已经到位。因此，我决定进一步研究静态代码。  
  
在查看静态代码时，我发现一个名为“   
**CardPrefs**  
 ”的类，其中包含一个名为“   
**getMobileNo()**  
 ”的函数，用于获取用户的手机号码。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusSZ4GsQrnAW80iaMXBVWOCycia4PqUiaJPoniaUuMLqNRyoS2biaicMKb6oicQ/640?wx_fmt=png&from=appmsg "")  
  
我编写了另一组代码来控制“   
**getMobileNo()**  
 ”函数。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuuscHOcicWyyTtG1XqwvwczGIL3l5hZO9sJp64G5PliaVdsTW9JeBCMTrRg/640?wx_fmt=png&from=appmsg "")  
  
在这里，我们可以将手机号码提供给 IDOR 的“   
**ret”**  
参数。现在是时候一次性运行整个代码了。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusePq5rbUL3hz84fMjvlWInJFhnulblar5j3QUA6PSIMxOMk57ZOawAg/640?wx_fmt=png&from=appmsg "")  
  
正如我所料，该应用程序容易受到 IDOR 攻击。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusOuBpGr2ZAd3fQxZpLn5u9weNxQuFst8BUqT8qWrVtPl7TGJp9fJ0Pw/640?wx_fmt=png&from=appmsg "")  
  
正在获取 81  
******  
**8 的卡详细信息  
  
如果你是一个长期主义者，欢迎加入我的知识星球，本星球日日更新，绝非简单搬运，包含号主大量一线实战,全网独一无二，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
部分更新内容展示:  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5egGySc9icfhF6HkeCWgec5NLp6v1CTqicao7jvgbghwKEfia1suMlEvMSQbzRLKjYPC3qWibH9l7q3w/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
## 往期回顾  
#   
# 如何利用ai辅助挖漏洞  
#   
# 如何在移动端抓包-下  
#   
# 如何绕过签名校验  
#   
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
  
  
