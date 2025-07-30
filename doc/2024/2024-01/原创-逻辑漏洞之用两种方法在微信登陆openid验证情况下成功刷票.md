#  原创-逻辑漏洞之用两种方法在微信登陆openid验证情况下成功刷票   
原创 酷帥王子  秦国商鞅   2024-01-07 09:55  
  
**最近一直在学习逻辑漏洞，偶然看到我家小孩学校组织的投票活动，得知老师组织这次投票活动，我专门向老师申请做一次逻辑漏洞测试，老师说非常欢迎，老师说对我这个玩电脑的家长早有耳闻，于是便有了以下的过程。此测试过程必须1、微信登陆下投票 2、token验证jwt加密，解密发现openid等参数**  
### 1、第一种方法突破微信登录投票  
  
一个微信账号一天投3票之扣别人的票增加自己的余票实现刷票首先用微信识别老师发来的投票二维码如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Qd6Zz1oqupaHLn22KyFbbnsgbcVicljhz54WicUEwSCkdJQY8dVyJ1OMSJ0oO3w68r72NlBjro09y4cww7DdUxDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
使用微信号登陆，不停的放包，直到这里  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Qd6Zz1oqupaHLn22KyFbbnsgbcVicljhzD7XXWG9ueQklK6mEbmdkGkLgnPCDu20jpcrC2LJ6D1xthJrHaM2hicQ/640?wx_fmt=jpeg&from=appmsg "")  
  
修改playerIdwei为别人的，因为用自己的playerid，自己的票数为变为-负数，修改num数为负数，如-9999，因为num参数可控，这时候你的票数会多出9999票，别人会少9999票，打个比方如图：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Qd6Zz1oqupaHLn22KyFbbnsgbcVicljhzSic7Bc27nZeh25z9f5gGicZblqUMhfNZZUfxX3OpJ1OMKU5ibbd55FEiaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这时候你就在你的账号不停歇的点投票就行，直到超过第一名，如图：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Qd6Zz1oqupaHLn22KyFbbnsgbcVicljhzFhl7LmUprBibTqO1kJzkrGiavHfoHiaNQlVicg21mV3ocFTFaHCyxnb6Eg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
票数瞬间变为1002票，本来一个微信号一天只能投一个选手3票，这时候已经成功突破，秒变1002票。  
  
以上是第一种方法刷票，扣别人的票，加自己的余票，然后再刷给自己… …  
### 2、 第二种方法利用long长整型溢出刷票  
  
同样到这个包，如下：  
```
```  
  
修改num=3333333{},如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Qd6Zz1oqupaHLn22KyFbbnsgbcVicljhz7JoRPcIdLlBOtTSXSYSiaoUDOI5ibLIAbakiaRrLm2ibL4CCmzzCIKLEng/640?wx_fmt=jpeg&from=appmsg "")  
  
  
判断为long长整型，既然num=-333333可控，那我们就把num=-333333改为2的63次方，也就是num=-9223372036854775808，执行完以后，提示500错误，提示超出范围… …然后微信打开投票二维码就卡半天了，恢复之前如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Qd6Zz1oqupaHLn22KyFbbnsgbcVicljhztu140nmEy2Qm5jTRMLxXpEAlo37po0FZk2l24biamricuopRFEaiavEQg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这是之前测试的时候不小心搞成，所以才有了第二种方法。  
  
也就是刷票数为负 -270多万，如上图。  
  
等溢出恢复以后票数变成15W多，排名第一，如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Qd6Zz1oqupaHLn22KyFbbnsgbcVicljhzF1B5qiaeBMNULtgI3xANm78ebticV0Mzfibv8LXEaEobnH7s7cW6SKcIA/640?wx_fmt=jpeg&from=appmsg "")  
  
注：由于测试过程没有保存录像或图片，导致溢出以后的返回包没能贴图，不过没关系，正负数都试一遍，一般参  
数可负数的话，直接负的最大溢出量就够了。  
  
  
