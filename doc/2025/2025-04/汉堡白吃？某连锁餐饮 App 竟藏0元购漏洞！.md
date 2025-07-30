#  汉堡白吃？某连锁餐饮 App 竟藏"0元购"漏洞！   
起凡安全  Z2O安全攻防   2025-04-23 13:14  
  
**前言**  
  
作为一名日常喜欢点外卖、又喜欢吃汉堡的苦逼大学生，我最近在某汉堡连锁店的点餐小程序里，发现了一个支付逻辑漏洞  
，可以实现0元购。当然，作为有职业道德修养的大学生，发现后第一时间上报了平台并协助修复。  
  
正文  
  
在开始之前，我们先看看正常  
的支付流程是怎么走的。一般来说餐饮系统是这个点单逻辑：  
  
   1. 选择商品（如汉堡+可乐套餐）→ 点击"立即购买"  
  
   2. 填写收货地址 / 选择到店自提  
  
   3. 进入订单确认页  
，显示总价、优惠券、实付金额等  
  
   4. 点击"去支付"→ 跳转至第三方支付平台（如微信 / 支付宝）  
  
   5. 支付完成后跳转回 App，订单状态变为"待接单"或"已支付"  
  
在常规的支付逻辑中，后端应该对以下关键字段进行**强校验**  
：  
  
 1. 商品价格必须由后台计算，不可信任前端提交的数据  
  
 2. 支付状态必须依赖第三方支付平台的真实回调  
  
 3. 优惠券使用逻辑必须绑定用户、状态、过期时间，并严格控制数量  
  
但很多时候，开发为了"快速上线"，往往在这些地方埋下隐患……这时候就是我们趁虚而入的时候喽，也就是在计算商品价格，或者是提交dopay的时候尝试改敏感字段。  
  
通常来说敏感字段有这些：  
```
productid 商品id
price 价格 
count 数量
discount 折扣
couponPrice 优惠券
payType 支付方式
payStatus支付状态
finalAmount 最终价格
```  
  
经过分析这个小程序计算购物车价格都是在后端，也做了价格的校验。数据包直接发过去商品id 购物车id ，然后计算。所以修改数据包价格是没有用的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4IsFHHvu0w4ImDr6rtVmU1Z3XS4MZZbMvyxmBqeiaxuw9ILib07IUVTbw/640?wx_fmt=png&from=appmsg "")  
  
关键在于提交支付的时候有一个submit接口  
```
{"memberId":"2336182439538851840",
"openId":"",
"storeId":"1162731767332864",
"orderFrom":1,
"orderType":2,
"userCouponId":"",
"couponCode":"",
"paymentCode":1,
"receiverName":"磊",
"receiverMobile":"",
"receiverAddress":"",
"remark":"",
"latitude":,
"longitude":,
"carList":
 [{"spuId":"1259209795738820608",
   "skuId":"1259209795780763648",
   "flavorList":[],
   "condimentsList":[],
   "copies":1,
   "setmealType":2,
   "singleList":
     [
     {"1264812338473361408":1},
     {"1264812338800517120":1},
     {"1264812339119284224":1},
     {"1264812339446439936":1}],
     "openId":"oHVqn65MyJWgPAgf_z7CudMd_cp0","isPurchase":0}
     ],
   "takeAwayTel":"",
   "appointmentTime":"立即取餐",
   "mainId":"undefined"}
```  
  
然后就是dopay接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4E6ibPGmcPNCd8ANcyOFb0NmdEpZQdSaTQEO2FJwiayKiadXHmlh6AFicow/640?wx_fmt=png&from=appmsg "")  
  
      
这里惯性思维肯定直接尝试直接修改dopay接口的价格，或者是同时下两个订单一个低一个高，直接改订单号替换支付，好吧都无果，全部都做了校验。然后这时候回头看Submit接口，有两个敏感字段 ：1.userCouponid 2.couponCode 那么有没有可能submit提交这里，可以伪造一个优惠券，然后提交上去，让服务端计算价格呢？  
  
    接着去burp里面找到了一个myCouponList接口，这里正好对应上了submit里面的信息可以填一下，但是这是我自己的优惠券，没什么卵用啊  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4jtWR99fITiauicT1RiaTwIxibdLLpOP08XgMh9xKpR75DPvwK3xicHI3IJw/640?wx_fmt=png&from=appmsg "")  
  
接着找到了一个counponList的接口，发送的数据包里有一个counponPrice字段  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4UJWbKQyTtR0KHnCAW930w5PZK9T9hQzAmU7nsVhLmpQCp38A3yPRyA/640?wx_fmt=png&from=appmsg "")  
  
根据前面的推测，submit接口可能是提交优惠券然后在后端计算价格。那么我们接着在submit的接口构造这个字段couponPrice为6，然后couponCode和ID直接置空试试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4icK5iaa64ELmP5YHEpunpwR7FBVX5lPXdA1dCP6q4CmDGUuoqxEqtPJQ/640?wx_fmt=png&from=appmsg "")  
  
成功了！dopay接口变成了11.5，然后发起了微信支付  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4szsX4Yd6VYQeuSgIfXeYRWXhKgW0pz1Cv6T6kru9KnAH6PjTCNcCuA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4pRCBe6eJRwkmf1licx9YBBBEFBIglLJDrseJ2J2gQicz5OpbnaaVibX0A/640?wx_fmt=jpeg "")  
  
  
后续尝试可以修改CouponPrice字段任意修改优惠券金额，最终实现0元购。这里我为什么没有0元购呢，因为我真的买了，0元购问题太明显....  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mAfQKBaPq5ezsSQ623dXZ4evib023mJia7U7Ooevu3LOsBjic1AOABsyXt2DPRAuwatPzUNNTibwKY7w/640?wx_fmt=png&from=appmsg "")  
  
附支付逻辑漏洞一些思路:   
<table><thead><tr><th><section><span leaf=""><span textstyle="" style="font-size: 16px;">绕过方式</span></span></section></th><th data-colwidth="284"><section><span leaf=""><span textstyle="" style="font-size: 16px;">举例</span></span></section></th></tr></thead><tbody><tr><td><section><span leaf=""><span textstyle="" style="font-size: 16px;">替换支付</span></span></section></td><td data-colwidth="284"><section><span leaf=""><span textstyle="" style="font-size: 16px;">支付低价格的商品来买高价格的商品</span></span></section></td></tr><tr><td><section><span leaf=""><span textstyle="" style="font-size: 16px;">最小额支付</span></span></section></td><td data-colwidth="284"><section><span leaf=""><span textstyle="" style="font-size: 16px;">修改价格为 </span></span><code data-start="944" data-end="950"><span leaf=""><span textstyle="" style="font-size: 16px;">0.01</span></span></code><span leaf=""><span textstyle="" style="font-size: 16px;">、绕过金额判断</span></span></section></td></tr><tr><td><section><span leaf=""><span textstyle="" style="font-size: 16px;">负数支付</span></span></section></td><td data-colwidth="284"><section><span leaf=""><span textstyle="" style="font-size: 16px;">使用 </span></span><code data-start="972" data-end="979"><span leaf=""><span textstyle="" style="font-size: 16px;">-10.0</span></span></code><span leaf=""><span textstyle="" style="font-size: 16px;"> 做付款金额，若系统未验证，可导致反向</span></span></section></td></tr><tr><td><section><span leaf=""><span textstyle="" style="font-size: 16px;">优惠券支付</span></span></section></td><td data-colwidth="284"><section><span leaf=""><span textstyle="" style="font-size: 16px;">重复使用优惠券、伪造未绑定优惠券 ID</span></span></section></td></tr><tr><td><section><span leaf=""><span textstyle="" style="font-size: 16px;">溢出支付</span></span></section></td><td data-colwidth="284"><section><span leaf=""><span textstyle="" style="font-size: 16px;">通过提交异常的金额值（如超出上限或负数）触发系统计算错误</span></span></section></td></tr><tr><td><section><span leaf=""><span textstyle="" style="font-size: 16px;">并发</span></span></section></td><td data-colwidth="284"><section><span leaf=""><span textstyle="" style="font-size: 16px;">万物皆可并发，</span></span><span style="font-size: 16px;letter-spacing: 0.034em;background-color: transparent;"><span leaf="">懂得都懂</span></span></section></td></tr></tbody></table>  
建立了一个  
src专项圈子  
，内容包含**src漏洞知识库**  
、**src挖掘技巧**  
、**src视频教程**  
等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaEwb07ryAplac3KXf8QkE5JSlU4iahMxnfDB6daPMUX2Ys9T7PlheOKe8ZgicIpicUxDzNW92w3t56Q/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
