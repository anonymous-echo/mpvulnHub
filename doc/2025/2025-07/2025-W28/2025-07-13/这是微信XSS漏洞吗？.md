> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNTU3MjA3OQ==&mid=2247485148&idx=1&sn=280d1d4f4a5c5819b526819228c350bf

#  这是微信XSS漏洞吗？  
原创 安全攻防屋  安全攻防屋   2025-07-13 11:44  
  
1、效果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFHBq4ZqQRXrMagAzKRBcxzSDdpzYogQicHgqk7NxynJDCAAicCNibmyUklNzXcaj6rhOHPnUKeGYh7OA/640?wx_fmt=png&from=appmsg "")  
  
  
2、payload如下：  
  
<a  
  
href="weixin://bizmsgmenu  
  
?msgmenucontent=诶呀妈呀  
  
&msgmenuid=960">你点一下试试看</a>  
  
3、复现过程：  
  
找一个微信联系人，引用其说的话，并复制代码，发送  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFHBq4ZqQRXrMagAzKRBcxzSo1KyvQMk1iaoIMnTcKFVN6XoiavjibZlO5A37BMwS0BLvoCrxOthYCmfw/640?wx_fmt=png&from=appmsg "")  
  
效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFHBq4ZqQRXrMagAzKRBcxzS6DDQAq6EhOtzyMicjSx78VvKUV9uzLuQeiakMTuPico11kxsEMHKibYia5g/640?wx_fmt=png&from=appmsg "")  
  
4、注意，有条件限制  
  
（1）好友需使用安卓手机点击，苹果系统目前测试不支持；  
  
（2）微信需更新为最新；  
  
（3）一定要引用对方的信息，否则只有对方看到的是源代码内容；  
  
（3）使用电脑打开查看也是看到源代码内容。  
  
  
  
  
