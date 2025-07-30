#  【CTFer成长之路】SSRF漏洞   
原创 儒道易行  儒道易行   2025-04-29 12:01  
  
## SSRF Training  
  
**题目描述:**  
  
web容器中存在一个flag，mysql中存在一个管理员账号密码，其余容器中均没有特定flag  
  
mysql容器中内置 tcpdump  
  
vulnweb容器中内置一个 fpm.py 攻击脚本  
  
**docker-compose.yml**  
```
```  
  
**启动方式**  
  
docker-compose up -d   
  
http://localhost:8233  
  
**题目Flag**  
  
n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r}  
  
**Writeup**  
  
进入环境  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAOM1edt6Pf3P4qUmXf6sTnx0o5jp8QZVoQSquwaKVbsx5qibjNaFGWOA/640?wx_fmt=png&from=appmsg "")  
  
点击interesting challenge  
  
开始代码审计  
```
```  
  
parse_url:  
  
代码：  
```
```  
  
结果：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUA4YoiaIJM1NFb1CuwnK7DiaEKbvHnEVwzhYRZVuaTaW4EDiasVUXGlh47g/640?wx_fmt=png&from=appmsg "")  
  
curl_getinfo  
  
代码：  
```
```  
  
结果：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUA0UHytM0DLxKIBJ76X8zjqBibn7mectSZOwDia5q9SbNibGr2ohYraEOqg/640?wx_fmt=png&from=appmsg "")  
  
payload:  
  
http://192.168.10.24:8233/challenge.php?url=http://a:@127.0.0.1:80@baidu.com/flag.php  
  
传入的URL为  
http://a:@127.0.0.1:80@baidu.com  
，那么进入 safe_request_url检测之后 parse_url取到的host是baidu.com  
  
代码：  
```
```  
  
结果：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUA7wVGib4iaz3vBtUeoypBZxeI9ZpuNR06QiaA4LNGknjd4Z4PNxQqzaK2Q/640?wx_fmt=png&from=appmsg "")  
  
而curl取到的是127.0.0.1:80，所以就实现了检测IP时候是一个正常的一个网站域名而实际curl请求的时候是构造的127.0.0.1  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAdGE3qc0oibHreuVicckibarDYDMCw9zia7t1wX2SlzsDtakwZ2F2iaY5ia4w/640?wx_fmt=png&from=appmsg "")  
  
得到flag：n1book{ug9thaevi2JoobaiLiiLah4zae6fie4r}  
  
接下来是攻击MySQL,打开2个MySQL容器，一个使用tcpdump，一个进行MySQL查询。  
  
使用docker ps命令找到mysql容器的command id为e2c90d571d32   
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUANp7Br20FmO2X7aDWHSARUETwqq7q6ydIWTCCsRiajp29iaj2ib2VAXp1w/640?wx_fmt=png&from=appmsg "")  
  
使用docker inspect e2c90d571命令查找mysql容器的pid为3602  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAyQ3VeLYrmsznXt5NibvG1qXRGeIR5WmSibsp1KxPPArmN8DdQTkDUBkQ/640?wx_fmt=png&from=appmsg "")  
  
使用nsenter --target 3602 -n命令进入mysql容器  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAsjpRJ1iaFUWnqqFFsvu6aXI8KI0Hvjiacc81qDvWpUUlS2UsKicQLr64w/640?wx_fmt=png&from=appmsg "")  
  
查看mysql容器的ip  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAWBDheBjkNxyXv4vn0mmia5HRjCOdic8rzowNVWXdj3LL49zibfUiclcuDA/640?wx_fmt=png&from=appmsg "")  
  
使用tcpdump抓取mysql容器内的包  
  
tcpdump -i eth0 port 3306 -w /var/www/html/mysql.pcap  
  
结果：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAn74d0Dsa0RHILLZ2M1gLibCc4OiccsfaMMJeRNrUBtDVZlh8OGe8azjg/640?wx_fmt=png&from=appmsg "")  
  
使用docker ps命令找到mysql容器的command id为e2c90d571d32   
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUANp7Br20FmO2X7aDWHSARUETwqq7q6ydIWTCCsRiajp29iaj2ib2VAXp1w/640?wx_fmt=png&from=appmsg "")  
  
使用docker inspect e2c90d571d32 | grep IPAddress命令找到mysql容器的ip为172.21.0.4  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAZVTSKrv78M9LPyTILuQwg72D6MSgWIASYayGxMDCNqz31AsbMLJH2A/640?wx_fmt=png&from=appmsg "")  
  
连接mysql  
  
mysql -h 172.21.0.4 -uweb  
  
使用ssrf数据库  
  
use ssrf;  
  
查询账号密码  
  
select * from user;  
  
结果  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAkkHTq4Ep28leLMzWtN4flNlZTje75c0a48Ae8wm9om4IcusZRhE6oQ/640?wx_fmt=png&from=appmsg "")  
  
用wireshark打开这个数据包,再随便选择一个包并单击右键，在弹出的快捷菜单中选择“追踪流 → TCP流”，过滤出客户端到服务端的数据包：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUA3dNCImgTaOuC894NTPc8LtAruaicbzIm0W9JoPfmCbD89Z19kU2QYrg/640?wx_fmt=png&from=appmsg "")  
  
把它转为原始数据，再将原始数据整理为一行，并将其url编码。  
  
这里用到的URL编码脚本如下：  
```
```  
  
得到：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAMNMsbqU8N9pT2SPOUaSA1kkH7e0Ukda3AXm6ErHYS872sx7WmaMBow/640?wx_fmt=png&from=appmsg "")  
  
将其修改为。ip可为MySQL容器的ip或者127.0.0.1  
```
```  
  
进行攻击，获得user表中的数据，运行结果：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxJYLvRV0lTQR7YNfuTqYUAq4hWsXxg5ibh10a0YegdoSfynpfymudBRF31hricaUWCzaw9nHrCLQmQ/640?wx_fmt=png&from=appmsg "")  
## 声明  
  
免责声明：该文章内容仅用于学习交流自查使用，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息、技术或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关，公众号儒道易行及作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
