> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MTg4NTMzNw==&mid=2247484497&idx=1&sn=e16cdc5c6ab692d33c57e2a5ae01e722

#  某信RCE漏洞  
 喵星安全研究所   2025-07-18 09:44  
  
漏洞分析  
  
X信3.9版本 1click rce 大概步骤是在转发聊天记录的时候，修改内存为图中的东西，X信会自动下载文件，把.lnk快捷方式放到用户启动目录，这样用户重启电脑的时候就会执行，造成rce  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZrRzUDtBZXOgfaab8vwOpWUg4xFD8SYt9aSaew6KAwkAs0eLMxvj3iag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZicsuz19UOF173ttmtZIYMw4KVhdgibDYafDuC42GU6FEblGiaUAklAtDw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZ7qo6eFiaj3ibcxGSUbhZib55rOicZ7odPGuzicLsckiax2BxMdMaXpyHL4ow/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GT0UFBibnWv4LU1IFjn5O4plmkibP8dFKZiblj1zOKMCmibbm0p0Lr9fBCuFQ4LsLXAACsm6q6x9dCiaPcLk2Olpn1A/640?wx_fmt=png&from=appmsg "")  
  
全过程  
  
【X信3.9版本存在严重安全漏洞，提交src竟被忽略？甚至在漏洞复现的第二天就被别人拿去利用？】 https://www.bilibili.com/video/BV1j3gTzsEbw/?share_source=copy_web  
  
注意事项  
  
不随意点击聊天记录中的陌生文件，来源不明的文档、图片等  
  
谨慎进行聊天记录的转发操作，避免转发可疑内容  
  
排查X信版本，并对涉及漏洞版本的X信进行升级  
  
