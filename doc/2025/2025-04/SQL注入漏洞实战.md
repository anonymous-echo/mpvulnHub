#  SQL注入漏洞实战   
原创 bcloud  蓝云Sec   2025-04-19 16:00  
  
声明  
  
任何网络安全相关测试均需取得授权， 本文章中所有内容仅供学习交流，严禁用于商业用途和非法用途， 否则由此产生的一切后果均与文章作者无关！  
  
前言  
  
一次渗透测试实战中的SQL注入 ，从延时注入耗费大量时间到用户名密码获取至整个网站数据信息泄露 的一次真实记录。  
  
渗透开始  
  
首先开局登录框  
   
，任意输入用户名密码  
admin  
:123456，不行，  
   
提示账号不存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPhRDsHveanxtxGiaEulnaquHtVNg4JLicIPGNZibbCNFl0fAZlWqicfoc7pQ/640?wx_fmt=png&from=appmsg "")  
  
这下不好搞了，  
   
爆破了一下也没有爆出账号名密码，  
   
索性查看了一下插件，  
   
发现  
SQL  
注入插件有响应，  
   
去看看，  
   
哎嘿  
500，  
   
200状态码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPheWmm26Jc1WtGpzopNibnq1ZGjRRZOsvLD9AiaKAkPbMPxtnmhxdffhLw/640?wx_fmt=png&from=appmsg "")  
  
  
先自己实验一下，  
   
account参数添加单引号服务  
器报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPhYia8Xm7vcLZ2vSYo9OLibEqLm6Sz1YdGefUUicmldzP8JLpsibaFibiadchA/640?wx_fmt=png&from=appmsg "")  
  
再次添加单引号进行闭合，  
   
正常输出，  
   
我一看这包有的啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPhx7E9ZCnsrQVTNaa19bAkLzC6Ob8gG8sLgkjlMEQQegCQLIBiaqBnDNA/640?wx_fmt=png&from=appmsg "")  
  
直接  
sqlmap  
工具梭哈，  
   
成功证明  
SQL  
注入  
   
，但是是延时注入，  
   
我一看这有点复杂啊  
   
，但是做一个安全人  
   
员肯定不能放弃  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPhKpBiaVsQtGfKE8DPpymIysJh6bl46R9GgbAOicg3q9M7CtOITzHPtI8Q/640?wx_fmt=jpeg "")  
  
  
直接--dbs爆数据库名， 数据库名还挺多， 其中有一个为该单位的缩写， 比如微信小程序（ wxxcx） 这样子的数据库， 那不就一一对应了嘛  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPh6I1ib52U0rY0WmqaJDPlP07RT3NyVufc5ktYh9uiaFSibFLBRscKu9CEg/640?wx_fmt=png&from=appmsg "")  
  
直接爆破表名，  
   
md  
，  
   
这里耗费了一两个小时都没注入完，  
   
索性爆破到  
xxx  
_  
user  
表，  
   
这一  
看就有戏啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPh1U0fkZNCudMBDticAqMUD3cw63UoqKQekEkmyrusPqTcBKokNW3ibicOQ/640?wx_fmt=png&from=appmsg "")  
  
这里在爆破  
user  
表中的列，  
   
又耗费了我一个小时左右才爆破完，  
   
最终  
拿到三个有用的列，  
   
这里有点粗心  
   
大意没有刚开始没有看见  
login  
_  
account  
列  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPhuCC9shyk0KqHFSAZPBDMd756HCR2XQFPlYSM6e5ficC4FW6Z7hnS3iag/640?wx_fmt=png&from=appmsg "")  
  
所以先爆破了password列， 哎嘿发现全是123456， 弱加密的md5  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPh5mceibocYLz35wfnyc1tYYX4aHh9oicIliaiazBA6Qvalbe9gmZfBCDkVg/640?wx_fmt=png&from=appmsg "")  
  
然后爆破了  
name  
列，  
   
有三个数据，  
   
其中只有  
1810  
xxxxxx  
的手机号回显与其它的不一样，  
   
显示禁  
用状态  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPhgSCBAFyqBqA9xGeeBC9Qn9kUCt56sUdsmnbmUGib5Gwd1F6Q5S0AkRA/640?wx_fmt=png&from=appmsg "")  
  
  
这里我再回过头去看  
user表中的列发现login_accout，  
   
哎哟卧  
槽，  
   
就是粗心大意之下，  
   
md又耗费了很久  
   
的时间，  
   
这里成功获取到五个账号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPhapZsGrpTMvLbc8rqYTfUoHiaafU7G6GibKVfZuG52NAGsxgFg2Hl6G4g/640?wx_fmt=png&from=appmsg "")  
  
其中13xxxxxxx开头的账号都是被禁用状态， 只有1896开头的能够使用， 这尼玛耗费三四个小时的延 时注入成功获取到账号名密码登录后台， 成功登录， 里面数据还挺多就不给大家看了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK5ibk9CwAVuhIDGDiaqPrfAPh9fW8WRZ5JtLweTnnH6HeQRjOWibg6qDWmLjpnpOQvFeo7Q0HIQ2XDAw/640?wx_fmt=png&from=appmsg "")  
  
  
