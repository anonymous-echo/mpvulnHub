> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU0MTc2NTExNg==&mid=2247492616&idx=1&sn=e72c65680e407d484b4ad48ca4c87918

#  SRC实战篇--一次运气爆炸的登录接口突破  
 实战安全研究   2025-07-15 02:00  
  
声明  
  
本文属于OneTS安全团队成员carrypan  
的原创文章，转载请声明出处！本文章仅用于学习交流使用，因利用此文信息而造成的任何直接或间接的后果及损失，均由使用者本人负责，OneTS安全团队及文章作者不为此承担任何责任。  
  
  
某SRC主站某系统存在一个验证码登录接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZK9QnVqzyRMUMnhCEu4Vx8YKrXdjzJsSWelqAILEyw6BIICTZUy561g/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
使用尘封已久的测试手机号字典进行爆破：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZOETia48FUUWQFCtPATnEuHqmSN9TTlEDwf8IBeLWnNGuy4PprH69icNQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZp4UWtlk2Hq229icjCk99GahWND0ZfCMEdhPkJaSiaCY3TSsorbAAMwnA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
结果发现有一个特殊的响应包内容为：验证码错误，请重新输入，这很大概率说明这个测试手机号是存在的，转念一想，测试手机号存在，岂不是也会存在固定的测试验证码，说干就干，  
直接开始进行验证码爆破，先自己手机号走一波，发现验证码是6位数的，也就100万次吧，直接开始爆破：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZgaicRBibaGQdzmtrpjWlO5NLlMnibVOp0EPbs0sHaj5HicNOBkW2LcY9VQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
意料之中，此处错误次数有限制且是针对账号的错误限制……  
  
停滞片刻，想了想，还有两个思路可以搞![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
：  
- 一是信息收集去找可能存在的测试验证码，提高成功率；  
  
- 二是继续爆破测试手机号，这些测试手机号的验证码应该都是相同的，爆破出来的手机号越多，成功的几率就越大。  
  
  
直接按第二个思路往下走，固定爆破出来的手机号后两位，看有没有连号的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZ79cFmQF2ebsCjp3JW3sP2kIMANqElsic4murfmNzicduubsTtZeuZS4w/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
成功获取80-89十个连号号码，  
但是一个号码仅能错5次，10个号码，也就是错误50次后继续被锁定，还是无法满足，这里就只能继续进行信息收集了，寻找可能存在的万能验证码，在谷歌、github、网盘等进行了漫长的搜索，发现如下的js：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZC3vfGlOJujB8iamkxUGbDlmWNaEAXVSvq2qub3Md7w5NKXZKnocQ0cg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
此处存在一些6位数字，将其作为字典进行爆破：  
  
一共28个，字典如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZuOLPG6J9WUZCen4a0FtPn5tgPtZZqR41QHVHxAtmMlQhRugA6wXMag/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZ6OPqgoZft7pVibeToZbibeibbhB5zEXcicYSc1HSXibxsV1WZZGIWv8TCRQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZrgcwPvF8mFsZnCALIvO40CZ3M3uw1OZceGdyFAI7dP0ete99gekbGg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
开始爆破：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZudpgU24cFNmVP2ibZSAmbj9QMc1ejvrWxhMdrgv49xQDhMEopcSbSkg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
用完了一年的运气，直接爆出了验证码，直接登录![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_43@2x.png "")  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DMcCGsuVF6CMjzIjMZDfXZ56sCGWuQ7trJ3PY0lSBSd3fB8sIPYKzxGGy7f3U90Dj7B3g5e7uRzg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
 最后，祝看到这篇文章的兄弟们都运气爆炸，接好运！！！  
  
  
   
  
服务器推荐（定期更新，建议收藏）：  
  
https://docs.qq.com/sheet/DZUFIQmxZSGJjY1RK?tab=BB08J2&_t=1728576431874  
  
