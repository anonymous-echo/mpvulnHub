#  【Pikachu】RCE远程命令执行实战   
原创 儒道易行  儒道易行   2024-11-08 18:00  
  
**在这片海洋中，若无法向上攀游，就只有往下沉沦，是要前进或是溺死，就得看自己的选择。既然这么不甘心，就变的更强！**  
## 1.RCE(remote commandcode execute)概述  
  
RCE(remote command/code execute)概述  
  
RCE漏洞，可以让攻击者直接向后台服务器远程注入操作系统命令或者代码，从而控制后台系统。  
  
远程系统命令执行  
  
一般出现这种漏洞，是因为应用系统从设计上需要给用户提供指定的远程命令操作的接口  
  
比如我们常见的路由器、防火墙、入侵检测等设备的web管理界面上  
  
一般会给用户提供一个ping操作的web界面，用户从web界面输入目标IP，提交后，后台会对该IP地址进行一次ping测试，并返回测试结果。 而如果，设计者在完成该功能时，没有做严格的安全控制，则可能会导致攻击者通过该接口提交“意想不到”的命令，从而让后台进行执行，从而控制整个后台服务器  
  
现在很多的甲方企业都开始实施自动化运维,大量的系统操作会通过"自动化运维平台"进行操作。 在这种平台上往往会出现远程系统命令执行的漏洞,不信的话现在就可以找你们运维部的系统测试一下,会有意想不到的"收获"-_-  
  
远程代码执行  
  
同样的道理,因为需求设计,后台有时候也会把用户的输入作为代码的一部分进行执行,也就造成了远程代码执行漏洞。 不管是使用了代码执行的函数,还是使用了不安全的反序列化等等。  
  
因此，如果需要给前端用户提供操作类的API接口，一定需要对接口输入的内容进行严格的判断，比如实施严格的白名单策略会是一个比较好的方法。  
## 2.exec ping  
  
因为靶场环境是ubuntu  
  
使用管道符 | 执行 ping x.x.x.x | whoami 相当于执行了两个命令 但是最终会显示 whoami 命令的结果  
  
后台命令代码类似于shell_exec('ping -C 4'.$ip)，造成了RCE远程系统命令执行  
  
输入x.x.x.x | whoami命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg2aVibmRAUJhNnnYmQEvnxvQPPIUG4mpcC8nv7d96hQDx9AicPBUchVVGA/640?wx_fmt=png&from=appmsg "")  
  
输入x.x.x.x | ls命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg2dNIYoTKoC7cIw6icibXzYwvRElc4x8DKQTLX25JuiaJStql5do5g9sTFQ/640?wx_fmt=png&from=appmsg "")  
## 3.exec eval  
  
查看源代码，发现内容提交后直接传入 @!eval中 ，如果不报错就会执行 ，如果报错就会输出一句话  
  
所以我们可以利用这个漏洞执行代码语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg29mJxJG9oDe7caNXJseXu0iazvB7xShE728h7qzERp9YDuqic9Maw1Wlw/640?wx_fmt=png&from=appmsg "")  
  
输入phpinfo(); 发现输出了phpinfo页面  
  
将用户输入的字符串当做php脚本了解析执行, 并且没有做严格的过滤处理, 导致了漏洞的产生  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg2ojTTGr3JhD8njuFPQS6BHVOypIHFHfxgcL1J9xibjbQLBuyC0r93suQ/640?wx_fmt=png&from=appmsg "")  
  
查看请求头可知请求类型为POST, 对应的参数为txt:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg2XOHQvcFrWT7btjIhIwR3tDzlsTicuvpr2vnO5s25JkPuHbzIPVL0B3A/640?wx_fmt=png&from=appmsg "")  
  
利用蚁剑进行连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg2SfXw7fXMibu67TFYCgTC5jKias7sEYBF67qSGicOEyRVBzBOUsB9icXsDQ/640?wx_fmt=png&from=appmsg "")  
  
修改请求头的submit参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg26Cjxb68xFNJK5nToQhP4ZVJYBicmxcumMpGh8jXaZQdT0AHFhvJKxoA/640?wx_fmt=png&from=appmsg "")  
  
成功连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw214oSgQhia92reoDwRYFg2ibCiaKFVO0tM95V91NzqJJxh2gmfcG2ViaeAXK9k2yPMHvib8CSicib2YU4A/640?wx_fmt=png&from=appmsg "")  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpz6nTnUXxxWARiaEoGZdeyCoVUmPWF8lfWvgLKBE1cBvM6EnrwEMOmZhicDSxuuUAG2yhj21SddgEhQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
