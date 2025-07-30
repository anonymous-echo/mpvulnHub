#  【工具分享】JavaSecLab综合且全面的Java漏洞平台   
秀龙叔  黑客之道HackerWay   2025-04-25 07:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZKJuQWhOtIFk0lVGu3Bc0vgej7AHibk0HvVg3HC2xibqIoMCdTuC3VK715sv2DtXt0qG1y0dCdHztiag/640?wx_fmt=png&from=appmsg "")  
  
简介：  
  
JavaSecLab是一款最全面的Java漏洞平台，提供相关漏洞缺陷代码、修复代码、漏洞场景、审计SINK点、安全编码规范、漏洞流量分析，涵盖多种漏洞场景，人性化的交互UI......  
  
![展示](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZKJuQWhOtIFk0lVGu3Bc0vgavgia9eic1h1CStoqQpYUb3SrRu6LyrWysy4LKskojeDdjvMIVz2zibLw/640?wx_fmt=png&from=appmsg "")  
  
支持漏洞模块：  
```
跨站脚本攻击、跨站请求伪造、CORS、JSONP、URL 重定向、XFF 伪造、拒绝服务、XPATH 注入。
SQL 注入、任意文件族、跨服务器请求伪造、XML 实体注入、RCE
逻辑漏洞（IDOR、验证码安全、支付安全、并发安全）、敏感信息泄露系列、登录对抗系列。
SPEL 注入、SSTI 注入、反序列化、组件漏洞。
```  
  
技术架构：  
```
SpringBoot + Spring Security + MyBatis + Thymeleaf + Layui
```  
  
部署方式：  
  
克隆项目代码：  
```
git clone https://github.com/whgojp/JavaSecLab.git
```  
  
本地部署-IDEA  
```
JDK 环境 1.8
```  
  
1、配置数据库（Mysql 8.0+）  
  
执行 sql/JavaSecLab.sql 文件。  
  
修改配置文件application.yml active为dev(项目默认是docker，如果在构建过程中出现数据库连接错误，各位可以在这里注意)  
```
spring:
  # Environment dev|docker
  profiles:
    active: dev
```  
  
2、  
修改application-dev.yml配置文件  
```
username: root
password: QWE123qwe
url: jdbc:mysql://localhost:13306/JavaSecLab?characterEncoding=utf8&zeroDateTimeBehavior=convertToNull&useSSL=false&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=GMT%2B8&nullCatalogMeansCurrent=true&allowPublicKeyRetrieval=true&allowMultiQueries=true
```  
  
![标识](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZKJuQWhOtIFk0lVGu3Bc0vgRtDya9efe41aSqXAibOhbZAa5siblOoXK17NxZ8Uw7CUNibobc3gc0fmQ/640?wx_fmt=png&from=appmsg "")  
```
初始用户/密码：admin/admin
备注：可在后台修改
```  
  
Docker 部署(推荐)  
```
条件：docker 和 Docker-Compose 已安装
如果docker部署时没有初始化sql文件（即数据库为空），则需要手动导入sql文件
```  
```
mvn clean package -DskipTests
docker-compose -p javaseclab up -d
```  
  
![图像-20240905225532698](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZKJuQWhOtIFk0lVGu3Bc0vgbMYibzNRYTaKibBBkEiabiaCIH2G6IHicN8F5gFIacW8ribUtAc46a6ObkaA/640?wx_fmt=png&from=appmsg "")  
  
![图像-20240905225532698](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZKJuQWhOtIFk0lVGu3Bc0vg3cDicuV7aTtKDww2YhJ4JcavNF5YiaibEKxn4iaemf0EzhOmxNiaIoviaeoA/640?wx_fmt=png&from=appmsg "")  
```
部署方案及部署疑问详见：
https://github.com/whgojp/JavaSecLab/wiki/%E9%83%A8%E7%BD%B2%E6%8C%87%E5%8D%97
```  
  
在线体验环境：  
```
http://whgojp.top/
账户/密码：admin/admin
```  
  
- 公众号回复“  
6662  
”获取下载链接  
  
**用您发财的小手点个赞鼓励一下吧❥(^_-)**  
  
**关注公众号便于更好的为您分享(#^.^#)**  
  
  
  
  
**免责****声明**  
  
本公众号“黑客之道HackerWay”提供的资源仅供学习，利⽤本公众号“黑客之道HackerWay”所提供的信息而造成的任何直接或者间接的后果及损失，均由使⽤者本⼈负责，本公众号“黑客之道HackerWay”及作者不为此承担任何责任，一旦造成后果请自行承担责任！  
  
  
谢谢 !  
  
