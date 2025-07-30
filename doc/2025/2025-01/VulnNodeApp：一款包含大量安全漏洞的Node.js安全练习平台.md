#  VulnNodeApp：一款包含大量安全漏洞的Node.js安全练习平台   
孔方兄  巢安实验室   2025-01-24 09:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxbzl7jZJ6kSk7cFOGFBRcuibJUf1udTDwKA1OVkeQ4micxdiaFC9ibAb3T9ENYa78lZy13GCOibibr6m1w/640?wx_fmt=png&from=appmsg "")  
  
关于VulnNodeApp  
  
VulnNodeApp是一款包含大量安全漏洞的Node.js应用程序，VulnNodeApp基于Node.js开发，本质上是一个使用 node.js、express 服务器和 ejs 模板引擎制作的易受攻击的应用程序。对于红队和蓝队安全研究人员来说，可以将其视作一个安全练习平台来使用。  
## 漏洞覆盖  
  
当前版本的VulnNodeApp引入了下列常见安全漏洞：  
> 1、SQL 注入  
> 2、跨站点脚本 (XSS)  
> 3、不安全的直接对象引用（IDOR）  
> 4、命令注入  
> 5、任意文件检索  
> 6、正则表达式注入  
> 7、外部 XML 实体注入 (XXE)  
> 8、Node.js 反序列化  
> 9、安全配置错误  
> 10、不安全的会话管理  
> 11、即将增加新的漏洞，例如CORS、模版注入等...  
  
## 工具要求  
> Node.js  
> Express  
> EJS  
  
## 工具安装  
  
由于该工具基于Node.js开发，因此我们首先需要在本地设备上安装并配置好最新版本的Node.js环境。  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
```  
## 工具配置  
### 应用程序设置  
  
1、使用 npm 安装最新的 node.js 版本；  
  
2、打开终端/命令提示符并导航到下载/克隆的存储库的位置；  
  
3、运行下列命令：  
```
```  
### 数据库设置  
  
1、安装并配置最新的 mysql 版本并启动 mysql 服务/守护进程；  
  
2、以root用户登录mysql并运行以下sql脚本：  
```
CREATE USER 'vulnnodeapp'@'localhost' IDENTIFIED BY 'password';
create database vuln_node_app_db;
GRANT ALL PRIVILEGES ON vuln_node_app_db.* TO 'vulnnodeapp'@'localhost';
USE vuln_node_app_db;
create table users (id int AUTO_INCREMENT PRIMARY KEY, fullname varchar(255), username varchar(255),password varchar(255), email varchar(255), phone varchar(255), profilepic varchar(255));
insert into users(fullname,username,password,email,phone) values("test1","test1","test1","test1@test.com","976543210");
insert into users(fullname,username,password,email,phone) values("test2","test2","test2","test2@test.com","9887987541");
insert into users(fullname,username,password,email,phone) values("test3","test3","test3","test3@test.com","9876987611");
insert into users(fullname,username,password,email,phone) values("test4","test4","test4","test4@test.com","9123459876");
insert into users(fullname,username,password,email,phone) values("test5","test5","test5","test5@test.com","7893451230");
```  
### 设置基本环境变量  
  
用户需要设置以下环境变量：  
> DATABASE_HOST（例如：localhost、127.0.0.1 等...）  
> DATABASE_NAME（例如：vuln_node_app_db 或您在上面的 DB 脚本中更改的 DB 名称）  
> DATABASE_USER（例如：vulnnodeapp 或您在上面的 DB 脚本中更改的用户名）  
> DATABASE_PASS（例如：密码或您在上面的 DB 脚本中更改的密码）  
  
## 启动服务器  
  
1、打开命令提示符/终端并导航到存储库的位置；  
  
2、运行命令：  
```
```  
  
3、通过下列地址访问应用程序即可；  
```
```  
## 项目地址  
  
**VulnNodeApp**  
：【GitHub传送门  
】  
## 参考资料  
> https://twitter.com/4auvar  
> https://www.freebuf.com/sectool/408168.html  
  
  
真心感觉自己要学习的知识好多，也有好多大神卧虎藏龙、开源分享。作为初学者，我们可能有差距，不论你之前是什么方向，是什么工作，是什么学历，是大学大专中专，亦或是高中初中，只要你喜欢安全，喜欢渗透，就朝着这个目标去努力吧！有差距不可怕，我们需要的是去缩小差距，去战斗，况且这个学习的历程真的很美，安全真的有意思。但切勿去做坏事，我们需要的是白帽子，是维护我们的网络，安全路上共勉。  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
