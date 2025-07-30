> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNzY5MTg1Ng==&mid=2247490046&idx=1&sn=3e3b0e6e437b0c67ab0fee641495004c

#  WX RCE漏洞  
菜狗  富贵安全   2025-07-19 00:36  
  
漏洞分析  
  
X信3.9版本 1click rce 大概步骤是在转发聊天记录的时候，修改内存为图中的东西，X信会自动下载文件，把.lnk快捷方式放到用户启动目录，这样用户重启电脑的时候就会执行，造成rce  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZib5MOfPp3KdtSdwwINE7GDrFMq8Aqeaxe2DJ3ibAH0NX85vxO4frNyyA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZkrVTBA9QU8RLwJtnWy7dlyV3aC4T1uibV33N0pU37TPthTtnerHT2XQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZgia9BLQja1FovFP6kJZ3EYm0d8NKTmA1A6v9Qiaib4xicicMibaccLRxJw3A/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZZUGXfVtEXaLd9uR34yicbBu8DWnAPL4N0rJmV7RdokNUN0GMnox9o7g/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
全过程  
  
【X信3.9版本存在严重安全漏洞，提交src竟被忽略？甚至在漏洞复现的第二天就被别人拿去利用？】 https://www.bilibili.com/video/BV1j3gTzsEbw/?share_source=copy_web  
  
注意事项  
  
不随意点击聊天记录中的陌生文件，来源不明的文档、图片等  
  
谨慎进行聊天记录的转发操作，避免转发可疑内容  
  
排查X信版本，并对涉及漏洞版本的X信进行升级  
  
  
以上分析来源于喵星安全研究所  
  
  
  
