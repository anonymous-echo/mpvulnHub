#  红队攻防实战之phpmyadmin-RCE集锦   
原创 各家兴  儒道易行   2023-12-10 20:02  
  
# 世界上只有一种真正的英雄主义，那就是认清了生活的真相后，仍然热爱她  
## phpmyadmin远程代码执行漏洞  
  
访问该页面，存在弱口令  
  
爆破进入后发现该php版本以及phpmyadmin版本信息，该版本存在远程命令执行漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpaPjNdMHH42lqVe56QWTnsrY0rHCN0xicBicpyYwbKlUpPhUJC6ZC4t5cw/640?wx_fmt=png&from=appmsg "")  
  
使用exp利用此漏洞：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpauydXVeYGhNwDUyqiaTTQ0Q0Sesb4UDfcQ3BptccN7fjYDxHNFGicfwVA/640?wx_fmt=png&from=appmsg "")  
  
成功执行命令，并且在test数据库下创建了一个名为prgpwn的表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpaNgkpGiclMbT3gLGJgtUCmjpLgZAPUCrI7g7FiahQiaqkJ2cMSeIorcTNw/640?wx_fmt=png&from=appmsg "")  
## phpmyadmin远程文件包含漏洞  
  
构造任意文件读取的payload并进行访问：  
  
可见/etc/passwd被读取，说明文件包含漏洞存在：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpamreLUNBwDqzdnIuoHbQXwgCZocUBvCFaB8Gw15ycKQd6958qibvxq8g/640?wx_fmt=png&from=appmsg "")  
  
访问SQL语句的执行页面：  
  
执行一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpaibgLKUt4JpbMKVICYf6vlZ6ruJlYywTabiak6UU8QYN3afewjfI6Y7fg/640?wx_fmt=png&from=appmsg "")  
  
查看sessionid（cookie中phpMyAdmin的值）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpaRTReJYSauNibavhOZZRDajOeLPcBOrN9RBnWZTyicdVqlwiaIRkSVUpDA/640?wx_fmt=png&from=appmsg "")  
  
包含session文件：  
  
成功包含phpinfo页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpaiaY0Lic2LjYTwHIiaKf8d3fic43moyO5WRRFejUWGUdcq44ZOXpv5SPadw/640?wx_fmt=png&from=appmsg "")  
## phpmyadmin反序列化漏洞  
  
可读取/etc/passwd：  
  
漏洞证明：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpamWV0fcKPRQrSD4yEbfWhcOB2b7etPibm7ob5feDJicjdb0wibicvIOjAicw/640?wx_fmt=png&from=appmsg "")  
## select into outfile写入webshell  
  
secure_file_priv的值如图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpawGJBHXsqEWAHr12ziacJ5IGrcqyniaNeW3ZjE8pQRBRltN1nlSJQn9kA/640?wx_fmt=png&from=appmsg "")  
  
写入一句话  
  
这里需要注意的一个点是路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpakulOLRA1HT0vOCNvPZOVh6yY78kfcyVUwEz91dGftFaWiclzTaia2gAQ/640?wx_fmt=png&from=appmsg "")  
  
成功连接webshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25Mpa4A0rsMWZI3LsBbEQxa5BKOdiaZovibhia4vbeFia967FC9arPHspibtay3Q/640?wx_fmt=png&from=appmsg "")  
## phpmyadmin日志写入webshell  
  
打开general_log日志读写功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpanA50xGU1sFXBSibOKiawzc2ibnicIHErzwePen7ibyUwIRfPhZ2wITXaXyg/640?wx_fmt=png&from=appmsg "")  
  
制作一个木马文件，要根据图中general_log_file中的绝对路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25Mpajnmteu2T9tjwQZZ35PBqYBfKJoWVpkpTib2O0wiaZWHpszx9MyPeNNKQ/640?wx_fmt=png&from=appmsg "")  
  
往这个木马文件中写入一句话  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25Mpa5uJFB6Y7KK78S6hrFDQiaQDmIxib8bibNGoicLMp3N3q9p7S74GTnh5Yuw/640?wx_fmt=png&from=appmsg "")  
  
使用phpinfo验证  
  
利用过程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MpaQLDkN2HTRO6T2acm1OLrVrAI4T0IgXPA8P1iaWm3uoU6kC4bp8QicMdg/640?wx_fmt=png&from=appmsg "")  
  
蚁剑连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwHoHQEEs8SaNPwQKE25MparZGBuhIj9GMuAKpqCwA6X7F8qbSyEoY9oZtc47EVItQyLRMW2NbhTw/640?wx_fmt=png&from=appmsg "")  
  
最后抹除痕迹  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：各家兴 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
```
```  
  
  
  
