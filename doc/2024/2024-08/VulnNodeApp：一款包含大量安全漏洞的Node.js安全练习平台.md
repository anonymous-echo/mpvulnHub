#  VulnNodeApp：一款包含大量安全漏洞的Node.js安全练习平台   
Alpha_h4ck  FreeBuf   2024-08-10 11:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于VulnNodeApp**  
  
  
  
VulnNodeApp是一款包含大量安全漏洞的Node.js应用程序，VulnNodeApp基于Node.js开发，本质上是一个使用 node.js、express 服务器和 ejs 模板引擎制作的易受攻击的应用程序。对于红队和蓝队安全研究人员来说，可以将其视作一个安全练习平台来使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3iclFPNQoWDNDd8kfNdjCE8NxB5ianZ4smHwcpwKxzJy1CLXO52cHRIzV7yicjJFGCNQLSIdibslVYduw/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞覆盖**  
  
  
  
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
  
##   
##   
  
**工具要求**  
  
  
##   
> Node.js  
> Express  
> EJS  
  
##   
##   
  
**工具安装**  
  
  
##   
  
由于该工具基于Node.js开发，因此我们首先需要在本地设备上安装并配置好最新版本的Node.js环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/4auvar/VulnNodeApp.git
```  
##   
  
**工具配置**  
  
  
##   
### 应用程序设置  
  
  
1、使用 npm 安装最新的 node.js 版本；  
  
2、打开终端/命令提示符并导航到下载/克隆的存储库的位置；  
  
3、运行下列命令：  
```
npm install
```  
### 数据库设置  
  
  
1、安装并配置最新的 mysql 版本并启动 mysql 服务/守护进程；  
  
2、以root用户登录mysql并运行以下sql脚本：  
```
CREATE USER 'vulnnodeapp'@'localhost' IDENTIFIED BY 'password';

create database vuln_node_app_db;

GRANT ALL PRIVILEGES ON vuln_node_app_db.* TO 'vulnnodeapp'@'localhost';

USE vuln_node_app_db;

create table users (id int AUTO_INCREMENT PRIMARY KEY, fullname varchar(255), username varchar(255),password varchar(255), email varchar(255), phone varchar(255), profilepic varchar(255));

insert into users(fullname,username,password,email,phone) values("test1","test1","test1","test1@test.com","976543210");

insert into users(fullname,username,password,email,phone) values("test2","test2","test2","test2@test.com","9887987541");

insert into users(fullname,username,password,email,phone) values("test3","test3","test3","test3@test.com","9876987611");

insert into users(fullname,username,password,email,phone) values("test4","test4","test4","test4@test.com","9123459876");

insert into users(fullname,username,password,email,phone) values("test5","test5","test5","test5@test.com","7893451230");
```  
```
```  
### 设置基本环境变量  
  
  
用户需要设置以下环境变量：  
  
> DATABASE_HOST（例如：localhost、127.0.0.1 等...）  
> DATABASE_NAME（例如：vuln_node_app_db 或您在上面的 DB 脚本中更改的 DB 名称）  
> DATABASE_USER（例如：vulnnodeapp 或您在上面的 DB 脚本中更改的用户名）  
> DATABASE_PASS（例如：密码或您在上面的 DB 脚本中更改的密码）  
  
##   
##   
  
**启动服务器**  
  
  
##   
  
1、打开命令提示符/终端并导航到存储库的位置；  
  
2、运行命令：  
```
npm start
```  
```
http://localhost:3000
```  
  
**项目地址**  
  
```
```  
  
**VulnNodeApp：**  
  
https://github.com/4auvar/VulnNodeApp  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://twitter.com/4auvar  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494663&idx=1&sn=8220aadcd0c1496c6ecbae5bc5fddee1&chksm=ce1f1698f9689f8e004a21a851d5d2987d45054bf636fad5abba5b977ae3ab342ce2a73b26f8&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494632&idx=1&sn=39d15121b9d4a665a970768a9b377194&chksm=ce1f1177f9689861d973b98e71492ef76d1894ad7e593b40c27fbdbee4417d4d1a1c24b36621&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
