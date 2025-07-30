#  企业SRC简单漏洞挖掘   
原创 青春计协  青春计协   2024-10-24 22:57  
  
GRADUATION  
  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MVPvEL7Qg0Gz8nMFbAuAFty9awwJb4ibP3ahLT1ATibpeOyECdaOzIxibbgojtibTE6vAlEwYAW6Ajp3OdicibMRjgJg/640?wx_fmt=png "")  
  
  
前言：  
  
  
  
企业SRC简单漏洞挖掘，几个例子分享  
  
  
  
  
  
  
A、短信轰炸：  
  
  
  
XX小程序——主页——注册用户——手机号——获取验证码（重复进行这一步，可重复获取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTMS82eaPB0OJDRbCDQiadMVdxPGGOxkdaH9K3pXUHUYToxBhUbPlPDdQ/640?wx_fmt=png "")  
  
  
  
  
  
  
B、验证码/不失效可爆破：  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTibicFYJhR7r0fmdThh2Jyia1gFU2IKNZXSwygWZlq6kE8nvbvBU45l43A/640?wx_fmt=png "")  
  
  
  
  
  
  
C、信息泄露：  
  
  
  
1、没注销之前：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTRicoZKEo7GM0n88ibkXhlKpUw0BQT6IbTOGUKxOGLApmvbhTB7C3W8JQ/640?wx_fmt=png "")  
  
2、注销再次注册：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTHuTrsAPKOIZyiciccUT6xeP1X4B01okgMYEua1dnY9ZNrKYspGZRUjag/640?wx_fmt=png "")  
  
3、新用户登录：  
  
（历史订单记录依旧存在）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTogibbvZwhC1sKMCluxniaFOwSQyu0hHjia8SY92GYVrDicbXqQME5zP6iag/640?wx_fmt=png "")  
  
  
  
  
  
  
D、支付漏洞  
  
  
  
1、最低充值“300”元  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTnMwqkWxAUxpo0JMFFz0WWYJQhYicnv0EI9j3qbpU8YpgRHrY3aBPf9g/640?wx_fmt=png "")  
  
2、BurpSuite抓取数据包，修改金额为100  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTBV0eiaooZT57L24gqJNVy7n8iaIr7rDwKTtCbuSoTvG9cicpMcwaqAKSg/640?wx_fmt=png "")  
  
3、待付款：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTSWK8Wjc0EPQvI0mkEhWWicx3BicrlZRs9zl2JGyL6sllwIARoibG1CZ7Q/640?wx_fmt=png "")  
  
  
  
  
  
  
E、小总结：  
  
  
  
      这些漏洞都是挺简单的，对于技术没有太高要求，刚接触漏洞挖掘的同学，可以按照这些方面去进行一个简单学习，记录一下。  
  
     有任何问题可以在最下方评论区留言/私信 ！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTichpEJlwbDeV0Jcxro4dRKgNcsQldic6I2lNwdicI1qK2Iut5eqQh4Cwg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/P0DiaOtaPBdoHMzO54t7T1tg3pjdGDyuTwMIOcapMFpvKvzpO2WZaUPxia4SRzPvZDXYJ2OXZvEMqP4YhDMeQPAw/640?wx_fmt=jpeg "")  
  
**编辑｜**青春计协  
  
**审核｜青春计协**  
  
