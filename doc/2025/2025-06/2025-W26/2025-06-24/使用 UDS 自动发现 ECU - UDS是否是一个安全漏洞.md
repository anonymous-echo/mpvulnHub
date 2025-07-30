> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2MDk1Nzg2MQ==&mid=2247625266&idx=1&sn=7d747f1cb8f470b24f724c87fde28ece

#  使用 UDS 自动发现 ECU - UDS是否是一个安全漏洞  
GRCC  IoVSecurity   2025-06-24 07:46  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CQb4KERYG3QA0ezCCjgRONQvXCf3wka7je04trwIyMqsDUWBubpwfiahXImiaoia7NnueGomOO28vicSZ5wEFFTa1Q/640?wx_fmt=gif "")  
  
点击上方  
蓝色字体  
，关注我们  
  
**/**  
**技术交流群****/**  
  
添加微信15021948198，申请会员下载ppt & 加入汽车网络信息安全、测试评价、汽车电子、自动驾驶技术交流群、招聘求职群、  
投融资  
合作群...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4I9YofUzaw6sx6CLycoM00evI54SibEsknfrfy0u6qfZiczveFVLqntWg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4YoGx9yx4nxXUFrhs8UXywbElgKVaFuJMZk43BNbJ7uuNJIM8YyjgFA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4EYALa4MEJdfYN8Qz3FAoKoKkEjlhOyXWZrExO1LVJcIKDxu0e8UUWQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia433XjJb49SPdLwjD3sIPSBMrvIWDnKGAhYPOm6GTibv4sCUsRWQQcxzw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4j68d17UGfE4OiapWwDGIrSMUGhNPJp33PrOwVcFkd7IP127TNiayFrHA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia42CXOWWJzNuZ9m0T88ogFummjxnV71Bf50uYByYFvthBhgpCmRl4dIg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4UrGW4h41lI2fDvH97OKIe4etRmUByYMRneNKzwuHicicg7thLqPIX5Gw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4SJCg6EJPraic3od8miaHT0YSlFW2kvtgDrEMwrJCDgyibXlNeqa5icwLHA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia42RzKqXooZMrNHTsUQjW821PblYMicwy58pVrmJHwELbDHZXKZicqoSHQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4zG6ib5U0NWGiaLxPs5j6NQn6bevU965ib1d7sDfiaoLX6tCmD2fAUn4B5w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4cdGyONXoTRCkibdjm0CSWUztUv4M7a3tvrtUAmrkAycqBqic1Gn54MMA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4IImLTXgCsgsBtX2JkCbGKOvLoFia8zgicmLNUpBWic5O1l7cHdY22vaBw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4I2kxyeMTBOCicJNqB1cUMIwn4tJcNyKJ9ZDIo0UibE7zOzqlicSiaprib7Q/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4ZdelicLXjDVyuMS6eZo05l7xzpOGm5GtYwlLVPOibVA0EepU706Cic3Yg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia456Ox8W3VmnEJkdm30tpkrYuzfCItRQxwRogPGKZGoWDz8SMBlflVcg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia47ghrMeSz12DV1ILSKeFQ4qPwSK5xXow4u8jahpXlQgsMofsjNVMYog/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4HsG7pRjVYRxSN17fOtqf83VicypCDkNOZ6au3tnDvWK6E4mwEb2bw9g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4zP1I0QW19J24SpKo88N3alBL7bQ4WR9UI2EichcFKkekjPWxEaK9TibA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4HqX8jGYnofgEkf83Yjr3VlB5RjdMMD5P2rDOb8sXszGOFGUhwErdWw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4onfgEMlFlibWd01LFLQmSSIbQsTaIIiaCagyJffn1jDRu907KeWuQUow/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4bawKian8IpibnLksicQn0dVMibkkSwVZlwFljN1Zt2rFnre6ZzOGrp6pVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4rgyl0sdicWuD9P0FGQZpqP9U3FaE9jHsI6KmmoEoTpNb8ibC23Xt4jVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4JdBUtjueicVMibsqRJ0HfZuoDqxyBZcT7kTIWtic7LhJGGeUlDnJwCFMw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4uJAQBjlMo5EwmqjpZnyBfQ6vRDKWHic1MOeOdCARqibPEyjwuNFLicibQQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4S3FlM13WCCwUib6lpMAKdia3rPiaEjPobmcicOQRpR6ytkSAyp13gwNPkQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4V07oud3qnJkP81yZ8XFWwCibDgVTRics1damtkTWlGvPnnfAX0wFRFcw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4tlVJibzeEPJAAH6qz6CWPjc1t6liaC3Yiaz8ibCEGnMRuibWkz3B22dhibpQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4iax1M3Kje93NYBwibbuqdAAMhoE7BRD6gaTERtgZExVPQQbfJXNcQjUw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4lIBorfuEicwic2FvTwibbrGkVMlXic48PnsjI6WvS9XUm4Ssic3Q4P2ZVew/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia41CNJYPgpgdibbNMu9MNQV7GAXblnRMYIDuibfdCIQaI5CcozfiaLnDEzg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4SjRRbGb6J9KiczVibz2UM7lT7QAzRibWTkcFsUnJic0mnJ7UZakuicktjoA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4SKTWVVS8MEDlGHuykWEPP4ia7MSlp42WuEbXdvPdRs3KK1znY6b6MMA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4EWxM0S2ibicLZsD2IorMVYIzCCjGla3AkL16mNyXFcPRTia3LNUsGibu8A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4n5xibk3eYEiaOPKJDazL62JTibv32BNSUh2ficYoYfsJUHcKGaKKKgSOOA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4Q3pV9EnWbTtKN2JuRAibapNNAS98x7ejqMkjicMnBibJaouRYvfawgazg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia45wWQCk1bPNyg39gia7nVy7n01lR4pUOjXj2wh5b9Wl9ibIGlvGwrSduQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4lEgbiaeTnPCWJpSrEvrE9kiaeUhl4VgJKDdkGzZ6RlEIuDvQwaW3ogyg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4581JibyADosdFiaySuQiaTvuEl7hVOQGgUueRIDWUfSon1Z185Ee0V8Mg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4h9JW1ickCHnJ7xiaJVRWyW8uBKpopAxENIrfm7CBcfU8ZJmZgUca28sQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4LLHm5pR9Un7LbqKWT4g78m026Et2ABDZT3LwKyicKggaEVFCuDLM7sw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4aHwQObY5mhW4K84l3cGhbsQbmtcEvdtJhFvalXpu72v0k6urqJJJNg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4ibn0PDKAx3SQyMGlgdJasRK1ialT2SUBl0mUatS5IiabPdBTSMpgL5XJQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4xovxF9jO988buPZDMW6d1wUWjdr1nUwicJkOGg3icDLbfT2u3neZJYxg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3VJ5u2SrIw6Iib1pJl908ia4FclcXa3rT21aVljrZjDLpqJ0d86VHBPfgj6oib4uSjtMPROdVoppSjQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iabwjyojLhA03PtxUnkNPREnt2F48ywfXLpDdDAjicOTPI8Q94tVLbJ58tbRs12iaXDKhUOW9gd4NlFA/640?wx_fmt=gif "")  
  
相关文章  
  
  
[静默禁用](http://mp.weixin.qq.com/s?__biz=MzU2MDk1Nzg2MQ==&mid=2247516355&idx=1&sn=63a68db754586b7adc670d37bdabce04&chksm=fc02d009cb75591feee889fbf6c84979d9bf298c06914a63697288047688ab4ac1d0fede2205&scene=21#wechat_redirect)  
  
[ECU](http://mp.weixin.qq.com/s?__biz=MzU2MDk1Nzg2MQ==&mid=2247516355&idx=1&sn=63a68db754586b7adc670d37bdabce04&chksm=fc02d009cb75591feee889fbf6c84979d9bf298c06914a63697288047688ab4ac1d0fede2205&scene=21#wechat_redirect)  
  
[，启用CAN总线盲攻击](http://mp.weixin.qq.com/s?__biz=MzU2MDk1Nzg2MQ==&mid=2247516355&idx=1&sn=63a68db754586b7adc670d37bdabce04&chksm=fc02d009cb75591feee889fbf6c84979d9bf298c06914a63697288047688ab4ac1d0fede2205&scene=21#wechat_redirect)  
  
  
[CANdid - 绕过 ECU 身份验证的隐秘垫脚石攻击](http://mp.weixin.qq.com/s?__biz=MzU2MDk1Nzg2MQ==&mid=2247584509&idx=2&sn=b66af41d7424792a966e770de9ef0994&chksm=fc03da37cb7453218eee93955bce8084d983a5e874f090f89faf2347097a8b275bb754f52722&scene=21#wechat_redirect)  
  
  
[保护基于 AUTOSAR 的 ECU 免受网络风险，以实现创新的移动性](http://mp.weixin.qq.com/s?__biz=MzU2MDk1Nzg2MQ==&mid=2247584509&idx=1&sn=ace95fd735b49fa3afba4dfbb40e67a4&chksm=fc03da37cb745321dc8e735b2ffc6009e91a9951bfb3eff444d2a376e49a071c059fa02d502e&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/MfTd6rd9CyvNRMW8I9cvI1CK5gKiaYqg2veTn9t9dAe1GxYic7pAvgvRIKNFickConFyX8AvW2reAq8GchJI6aBpA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3mtDUr1XuyW2cYG7Sw2EiaUrea3t4ogqdJwheZChf1oxpNbrdfASs0NaXpeCe0UX0fjAOKpcCia0Iw/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm0gS0uHpiblBwuOoicp3VsHkfiawbEBGHGwt1TJkyALdfNgYwl8ic3CmSzdr8hI7Qg0OfZMA0d6Y1enyw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm0IDRYOFLl2XY8nUgX5iaUL7KV9Dr2UTjQBXXZGlwDOPNbVyedZcLn3Z5sEqW0PEwwuLU7b7lRAvwA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3blv4rkY4Rb273UGM23NhicAN2ZR203uG08ubJox357DvePVib6R0WciciaqnicS1nrR3k8ianibkvjFCKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3mtDUr1XuyW2cYG7Sw2EiaUzLVR34dPLh7X6S455ib0RmtTrKMFGaCpHFHeCZ3LbDq8jw66s9KMwtA/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm3mtDUr1XuyW2cYG7Sw2EiaU1nZgTyoGxRdBsNDiahQUxiad8UibAob7t3tL8I7gxLsYBNYvib8kjmibS2w/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/8Pvibnf7ic0cy77VtN8ibA7XuZgvGQoicjpar7CWkfIEXV4CEjiankS0tjDZEUgxhNHf0HicpBNcO4YuhOm5eIdb7RaA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/9yhibG49kQicogTWBZcB6XwgTib9lH6QN57pFdZwoRicFbc3JLM7icu8hadyzRKztBHGZ7eDEVgMiaHYqExfhbbpb5vA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/uTSIm9RGwm2F3KDtuNYvmkK20aeBw5tzC4P9ibHF9ZvNa8C5jrwloaUH0C7GHj5j9icJh7XicdFckbQ3M0sSlKs8w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
扫描二维码**申请**  
会员**下载ppt**  
 &   
加入  
  
网络信息安全、测试评价、汽车电子、  
  
自动驾驶、招聘求职等行业交流群  
  
获取合作机会  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/kuhNyShuqyAGSIk680L6OHthYzkwuUDkKqfw3icohb1JLrEvjicKgfaiatIDP1L7RN7zPQkzbrksWzTMmgh5LKjzA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/uTSIm9RGwm0ibSggKRaicPibLl2nXk3lGdgeoXo0P9Xy8e2aNHPm3LOhKjicHk2zhB5V1ar3CwUTs258UkiaTPYq4gw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
扫描二维码获取  
  
更多精彩  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/XiacM3aibSNia0qvdL1PUiaZugASarnXx5wAxT5ic13sgRB49E67AsdWeZpHnibUEW2oibToqEWRjHmImztgv33MaknnQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
关注“**IoVSecurity**  
”  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/fBQwicMRtG3qyicHcTibNaG9RMs2E8knzWpfH0gnibzKsciaBTYdnW8mFyNgvEAqBNoib29iasxMgwh2gWRSIkINyHVLA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/D7nIuxbSmauhlzDVRGHTibAGyGcFvY5qFSPyZdMCxTSXwjhzFTotRe6rciaIxatoAHF0MPI73MMPAbf0UUMIMSvw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点个在看  
你最好看  
  
  
  
