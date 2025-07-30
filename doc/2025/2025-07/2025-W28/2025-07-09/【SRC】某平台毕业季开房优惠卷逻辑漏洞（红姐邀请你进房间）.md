> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247490818&idx=1&sn=b8b5e7f8dc6be896a96fc042718d0e5f

#  【SRC】某平台毕业季开房优惠卷逻辑漏洞（红姐邀请你进房间）  
原创 ashui  Rot5pider安全团队   2025-07-09 08:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6nNyjd9QeAUdlJnqcbr4YsiaJBYGWoeEEFUicUo1STkXfMNjmDrdbO9Jf04Q6luKiaYAyjTWMQuofCg/640?wx_fmt=gif "")  
  
  
点击上方蓝字  关注安全知识  
  
#### 背景说明  
  
本次活动沿用**520期间的优惠机制**  
，用户可通过技术手段获取隐藏的测试优惠券（50元无门槛券），仅需支付0.01元即可兑换。以下为详细操作流程。之前也发过一篇。  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247490542&idx=1&sn=6e3e3be4bd3c0d1ee9b48f681b69b1b7&scene=21#wechat_redirect)  
  
### 核心步骤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqE4Gs5sU01iaysNAibeC5MLhE31wRr74UGlicopCDLmox6WmutRUE3Z8q6g/640?wx_fmt=png&from=appmsg "")  
  
随便领张券  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqEBVMa5vDFz9YibouSrXb1jYD3ggtIwvFFEr1Cic4llChZEoP0uR5JR2Sw/640?wx_fmt=png&from=appmsg "")  
  
抓包，找到这个接口，通过分析，spuid代表的是活动，该接口返回的是活动下的优惠券id，也就是后面截图里的skuid。(post传了很多个参数，但都是无效的，只有这个spuid参数是实际需要的，故厚码一下，只看关键部分)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqEGZ8zw48EDcvE4icQASRfwUcIvgEv31O7xKqX9114ThBpZutCS92oLRg/640?wx_fmt=png&from=appmsg "")  
  
Spuid为：A9999xxxx，这种格式，只有后四位是有变化的，通过遍历，找到很多个活动，且每个活动都显示创建者，如张三李四，其中有一个创建者为超级管理员的很特别。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqEveReBsgWaEmGC5aMyTBN9WicgSzWzwFtlFVciaLJ6wHdS6PNLQEia4Hnw/640?wx_fmt=png&from=appmsg "")  
  
可以看到 spuid为A99991009的活动下有skuid为A99991009001的优惠券，从这个包中，找到了测试的优惠券ID  
  
OK，接下来就可以在买券的接口请求包中替换skuid和spuid了  
  
找到任意一个下单的包，将原本的spuid和skuid替换为测试活动spuid和测试优惠券skuid  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqEU7fUwFls2Hhicrd8bZQHMFdFaRaor2opN9cpUO6ic9SHiacjic7NZ53Hsw/640?wx_fmt=png&from=appmsg "")  
  
成功生成订单  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqEtLUtCrsib1JBVwTicw70kfXcBr2icm7iaZjRFNW4PJB2IZc2ibD0pHGRNoA/640?wx_fmt=png&from=appmsg "")  
  
付费0.01元就买到无门槛50元券咯  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqEKqoZ1kuJp0JBueZYPK8OicAzpvKX7ichicDVWdJKzSu9IQrBGWgibgvAqQ/640?wx_fmt=png&from=appmsg "")  
#### 1. 定位关键接口  
- **目标接口**  
：获取活动优惠券列表的POST接口  
  
- **有效参数**  
：
```
spuid
```

  
（活动ID）  
  
- **其他参数**  
：文档验证发现，除
```
spuid
```

  
外其他参数均无效（已厚码处理）。  
  
- **参数格式**  
：
```
spuid
```

  
为
```
A9999xxxx
```

  
形式，**后4位可变**  
（如
```
A99991009
```

  
）。  
  
#### 2. 遍历活动ID寻找测试入口  
- **方法**  
：修改
```
spuid
```

  
后4位（范围建议
```
0000-9999
```

  
），批量请求接口。  
  
- **关键特征**  
：筛选返回结果中
```
创建者
```

  
字段为 **“超级管理员”**  
 的活动。  
  
- **示例**  
：
```
// 请求成功响应示例
{
  &#34;activity_creator&#34;: &#34;超级管理员&#34;,  // 目标特征
  &#34;coupon_list&#34;: [
    {&#34;skuid&#34;: &#34;A99991009001&#34;, &#34;type&#34;: &#34;无门槛券&#34;}
  ]
}

```

  
  
> “  
> 💡 提示：通过遍历发现 
```
spuid=A99991009
```

  
 的活动符合条件。  
  
#### 3. 提取测试优惠券ID  
- 目标活动（
```
spuid=A99991009
```

  
）下存在优惠券：  
  
**
```
skuid=A99991009001
```

  
**（即50元无门槛券的ID）。  
  
#### 4. 替换下单参数完成购买  
- **步骤**  
：  
  
- 原
```
spuid
```

  
 → 替换为 
```
A99991009
```

  
  
- 原
```
skuid
```

  
 → 替换为 
```
A99991009001
```

  
  
- 抓取任意酒店下单请求（需包含
```
spuid
```

  
和
```
skuid
```

  
参数）。  
  
- **替换参数**  
：  
  
- 提交修改后的请求。  
  
- **结果**  
：成功生成订单，支付 **0.01元**  
 即可获得优惠券。  
  
### 优惠券使用规则  
  
<table><thead><tr><th style="color: rgb(53, 53, 53);font-size: 16px;line-height: 1.5em;letter-spacing: 0.04em;text-align: left;font-weight: bold;background: rgb(219, 217, 216) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">属性</span></section></th><th style="color: rgb(53, 53, 53);font-size: 16px;line-height: 1.5em;letter-spacing: 0.04em;text-align: left;font-weight: bold;background: rgb(219, 217, 216) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">说明</span></section></th></tr></thead><tbody><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">券类型</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">无门槛（满0元可用）</span></section></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">面额</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">50元</span></section></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">使用范围</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><strong style="color: rgb(248, 57, 41);font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgba(0, 0, 0, 0);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;margin-top: 0px;margin-bottom: 0px;margin-left: 0px;margin-right: 0px;padding-top: 0px;padding-bottom: 0px;padding-left: 0px;padding-right: 0px;border-top-style: none;border-bottom-style: none;border-left-style: none;border-right-style: none;border-top-width: 3px;border-bottom-width: 3px;border-left-width: 3px;border-right-width: 3px;border-top-color: rgba(0, 0, 0, 0.4);border-bottom-color: rgba(0, 0, 0, 0.4);border-left-color: rgba(0, 0, 0, 0.4);border-right-color: rgba(0, 0, 0, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><span leaf="">仅限小程序端使用</span></strong></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">适用酒店</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">以预订页面实际展示为准</span></section></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">有效期</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">未注明（建议尽快使用）</span></section></td></tr></tbody></table>  
### 注意事项  
1. **合法性**  
  
1. 此方法依赖接口遍历，可能违反平台规则，**仅限测试环境学习使用**  
。  
  
1. 生产环境操作存在账号风控风险。  
  
1. **技术门槛**  
  
1. 需掌握抓包工具（如Charles/Fiddler）及基础HTTP协议知识。  
  
1. **信息保护**  
  
1. 敏感参数（如商户ID、Token）已厚码处理，实操时需自行抓取真实参数。  
  
### 附录：接口逻辑示意图  

```
graph LR
  A[遍历 spuid] --> B{创建者=超级管理员?}
  B -- 是 --> C[获取 skuid]
  B -- 否 --> A
  C --> D[替换下单参数]
  D --> E[0.01元支付成功]

```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KB8RYbicheV8HXTuEXQ0icqEwNyrhwRGDm8VPWicOhSFeVN6oN7LIFr2zQSaV52aOGaOLNnMrp9x17g/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
【限时  
6  
折！华普安全研究星球：以  
原创实战  
为主+SRC/内网渗透核心资源库，助你在漏洞挖掘、SRC挖掘少走90%弯路】当90%的网络安全学习者还在重复刷题、泡论坛找零散资料时，华普安全研究星球已构建起完整的「攻防实战知识生态」：  
  
✅ 原创深度技术文档（独家SRC漏洞报告/代码审计报告）  
  
✅ 实战中使用到的工具分享  
  
✅ 全年更新SRC挖掘、代码审计报告（含最新0day验证思路）  
  
✅ 漏洞挖掘思维导图  
  
✅内部知识库目前建设中、后续进入圈子免费进入  
  
【  
实战为王  
】不同于传统课程的纸上谈兵！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGQBVaictTrzLs9G2yyia77mBTnW7m4Zx2OQfcbz5b5DbdrradsQNkpHNQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTxJibeicaQ0uttmutBuckibQFCEVicpyhhWXprQVOn4AnAnpDauQiaWTblMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT9hvFFPpSupL0Q8d0Yv1F7dYxGZJjcKxHYTyiayhMI3xcVRoQhSs9VTQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTh0eO1DbG0onZph7o1AMPVU65ZjE5T9QH8XeMU0WNE5HiaUibNTBcQyyg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTpXhxBicMHYsw8hotg4abR2gdaqYkfGPhX8EeNPcibAAs89qcOWl8Sqdw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTJvsQnibaNk5WSuwpkDvkZTIFqN3XyKic4Mg5qI91sjNGQtibJRbEfIxgw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1JJ8n2ibazrLMZicuXbFatE1eibEBguAHWUUo9DJiabXiauibCYNC7EGD83ia1ZwHe7ySnUqmgKuANrnvXpQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
  
**后期我们将持续发布原创代码审计、src等漏洞挖掘文章，后期有些源码、挖掘思路等也会放进圈子哈~**  
  
**有任何问题可后台留言**  
  
  
  
  
往期精选  
  
  
  
围观  
  
[PHP代码审计学习](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484594&idx=1&sn=89c96ed25e1f1d146fa3e67026ae0ca1&chksm=c051ecd2f72665c45d3e8c51b94629319b992f7f459d5677d7ce253eac99fc5e2e8f78684907&scene=21#wechat_redirect)  
  
  
丨更多  
  
热文  
  
[浅谈应急响应](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484589&idx=1&sn=80ff6dbb4471c101a71e203a10354d59&chksm=c051eccdf72665db0530fce6a332bf44392fb0c4d3d61496c9141bb93ece816cbbe97f89d06f&scene=21#wechat_redirect)  
  
  
丨更多  
  
·end·  
  
—如果喜欢，快分享给你的朋友们吧—  
  
我们一起愉快的玩耍吧  
  
  
  
【免责声明】  
  
"Rot5pider安全团队"作为专注于信息安全技术研究的自媒体平台，致力于传播网络安全领域的前沿知识与防御技术。本平台所载文章、工具及案例均用于合法合规的技术研讨与安全防护演练，严禁任何形式的非法入侵、数据窃取等危害网络安全的行为。所有技术文档仅代表作者研究过程中的技术观察，不构成实际操作建议，更不作为任何法律行为的背书。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicDTm83Sic86kzBCzlXI5OiazEoc5ZrPHHWsRb80WlZcKRll5xOU2s5JKw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
  
