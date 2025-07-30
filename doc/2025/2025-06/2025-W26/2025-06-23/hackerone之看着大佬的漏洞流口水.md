> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MjU2MjY4Mw==&mid=2247485036&idx=1&sn=ee3a749d2edcc53ccbb3bdbbfbb4733f

#  hackerone之看着大佬的漏洞流口水  
pippybear  安全无界   2025-06-23 14:39  
  
声明：  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果  
与文章作者和本公众号无关。  
  
最近梅雨季和躺平最配啦，人呀，有时候就很奇怪，有着时间不想着捡捡漏洞，就喜欢看大佬的报告流哈喇子（没错，说的正是在下，上篇说的分享重复的漏洞后续等厂商修复了再分享哈，其实想想似乎也没有啥可分享的，就比较简单，毕竟在下只配捡洞）。  
  
话不多说直接上正文，最近周末看到  
2  
份公开报告，之所以要分享它们，主要也并不是因为它思路不错而分享，主要是想把他的赏金亮出来羡慕羡慕（天天自问：为啥不是  
me  
的）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gTWH8ia7WFVU4T4ibfwXcxbVoxN3O2aoaLwfTiaVv4hpbxjDjujJibXMo23Ta6B3B3SvkLic7cym5gc0Fg/640?wx_fmt=png&from=appmsg "")  
  
2  
份报告都是和绕过限制有关，其实思路大家估摸着都熟悉的一批啦，但是就是挖不到，只能看着大佬的嘎嘎赚，问题来了这是为啥呢。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gTWH8ia7WFVU4T4ibfwXcxbVovEwAoEEy0Y37oyAYNvKSAt1DGh53xWY5ZAYlazibvacpiaC49JT6Fs3A/640?wx_fmt=png&from=appmsg "")  
  
第一份报告，比较典型的  
host  
碰撞。这里原理就不用讲啦，相信各位大佬都玩到手软啦，直接上大佬的报告。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gTWH8ia7WFVU4T4ibfwXcxbVoygiaYnKKCBTW5NhJVNLHkB4zPsibg44avvq24RLaMBNC7BichyrCx1c7Q/640?wx_fmt=png&from=appmsg "")  
  
比较朴素哈，但这不是重点，重点是赏金呀，白花花的美刀，刺溜刺溜，嘎嘎舔屏。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gTWH8ia7WFVU4T4ibfwXcxbVoCmgApv7vdR99kibgMx9DhlsvQyXciaCD7Eq2NEdeQ4t3Zhc3GmGy8AvA/640?wx_fmt=png&from=appmsg "")  
  
另外一份报告，更加简单丝滑，  
XFF  
头绕过，  
emmmm  
，为啥我就遇不到呢，而且大佬这里的报告似乎按道理讲没有太说得出来的危害，因为只是绕过了限制，但是并没有啥敏感信息泄露  
 or   
利用情况。在国内估计已经被嘎嘎忽略啦。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gTWH8ia7WFVU4T4ibfwXcxbVoFoyEQzFD8TPP8RU7z4Sibq1kbjDm0dhYcwE9KPiavibzZwXumdHFhbia5A/640?wx_fmt=png&from=appmsg "")  
  
但是国外厂商似乎认可啦，出手真大方（这不是反话，是真羡慕）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gTWH8ia7WFVU4T4ibfwXcxbVob8G3kQKG6LtQmqmBaNvQ6fawFu9dkTwm0qgdYQTWCMWWsk7FZE2dog/640?wx_fmt=png&from=appmsg "")  
  
  
