#  【安全圈】GitHub 修补GitHub Enterprise Server 中的三个漏洞并建议企业用户紧急修补   
 安全圈   2024-08-24 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
github  
  
  
GitHub 发布了针对 GitHub Enterprise Server 产品中三个安全缺陷的紧急修复程序，并警告称黑客可以利用其中一个缺陷获取网站管理员权限。  
  
  
最严重的漏洞编号为CVE-2024-6800，该漏洞允许攻击者操纵 SAML SSO 身份验证来配置和/或获取具有站点管理员权限的用户帐户的访问权限。  
  
  
该漏洞的 CVSS 严重性评分为 9.5/10，被描述为在使用特定身份提供者的 SAML 身份验证时 GitHub Enterprise Server (GHES) 中的 XML 签名包装错误。  
  
  
安全公告显示：“此漏洞允许直接通过网络访问 GitHub Enterprise Server 的攻击者伪造 SAML 响应，以提供和/或获取具有站点管理员权限的用户的访问权限。利用此漏洞将允许未经授权访问实例，而无需事先进行身份验证。”  
  
  
GitHub 表示，该漏洞是通过其漏洞赏金计划私下报告的，影响GitHub Enterprise Server 3.14 之前的所有版本，并已在 3.13.3、3.12.8、3.11.14 和 3.10.16 版本中修复。  
  
  
该公司还记录了一对中等严重程度的漏洞，这些漏洞允许攻击者更新公共存储库中任何问题的标题、受让人和标签；并使用仅具有内容：读取和拉取请求：写入权限的 GitHub 应用程序从私有存储库披露问题内容。  
  
  
GitHub Enterprise Server 是 GitHub Enterprise 的自托管版本。它安装在本地或私有云上，并提供基于云的 GitHub 版本的功能，包括拉取请求、代码审查和项目管理工具。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliajBKp3MFEXDJWg0DR4GkbC6nLIBPdIAicZAmLAicCgWL6HqUHicqooNv9pAQiaEab4FB4uJ0HQac2atQ/640?wx_fmt=jpeg "")  
[【安全圈】为逃避赡养子女义务，美国一男子黑进系统让自己”去世“](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063804&idx=1&sn=1db6cd05680ef153f7a4ddd3d0c6aa2d&chksm=f36e647cc419ed6a577bb04d77e9d08d3af4775e9380dde0f786938e9de4bd0a48e84591ae62&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliajBKp3MFEXDJWg0DR4GkbCMp4OaAnJuVy1fU9SV8e8NVYiap7a7UXrhmA6uoH2mcGnYKaLDpgvnGQ/640?wx_fmt=jpeg "")  
[【安全圈】黑客炫耀世界上最大的ZIP炸弹，达到1148857344 Quettabytes](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063804&idx=2&sn=0c0db7f910205b4b477b1d3aecac5c94&chksm=f36e647cc419ed6ae6a5dcd22b3159f1cecee540f16daa2e8283795f35dc127bdb863d4c0938&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliajBKp3MFEXDJWg0DR4GkbCe72BrWfRaicjF0ViaJfWx069Lcjic20x13tkmkomrEx2NHqvaqqSQVwCQ/640?wx_fmt=jpeg "")  
[【安全圈】官方强烈建议更新，关键漏洞影响GitHub Enterprise Server 所有版本](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063804&idx=3&sn=5154e9390560d2ebe8fa774e0cee72df&chksm=f36e647cc419ed6af187ec7fc3d69ef2235f10cdd74588aff129d9e9c2cf160662c839e14d2d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliajBKp3MFEXDJWg0DR4GkbCDJUppM0t9Z8MMOaIzBzH7avibqXKelL91bMunOkDVjkqPRqFXtnxa3Q/640?wx_fmt=jpeg "")  
[【安全圈】NGate安卓恶意软件可利用 NFC 窃取 ATM 内资金](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063804&idx=4&sn=2939ce23cbfef70df8e046dfecf109af&chksm=f36e647cc419ed6abe22e0c2c88509237575f253e63f5ea1911c5f805e39fa9d1bc1245f982b&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
