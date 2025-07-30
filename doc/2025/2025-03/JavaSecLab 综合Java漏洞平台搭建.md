#  JavaSecLab 综合Java漏洞平台搭建   
原创 moonsec  moonsec   2025-03-08 12:32  
  
# 一、介绍  
  
 JavaSecLab是一款综合型Java漏洞平台，提供相关漏洞缺陷代码、修复代码、漏洞场景、审计SINK点、安全编码规范，覆盖多种漏洞场景，友好用户交互UI……  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwAZHItQiasXRRH2lvDvygsticc3zkNU57PUfWnTfjpicJ4fssq974ia2hDg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwiaibuyQfyiaoOwJkJcw2ibFLiataJ78RwsuFI2uYBDic2XJRRLJqEBy2aCZA/640?wx_fmt=png&from=appmsg "")  
  
**支持漏洞模块**  
  
跨站脚本攻击、跨站请求伪造、CORS、JSONP、URL重定向、XFF伪造、拒绝服务、XPATH注入  
  
SQL注入、任意文件系列、跨服务端请求伪造、XML实体注入、RCE  
  
逻辑漏洞(IDOR、验证码安全、支付安全、并发安全)、敏感信息泄漏系列、登录对抗系列  
  
SPEL注入、SSTI注入、反序列化、组件漏洞  
  
**技术架构**  
  
SpringBoot + Spring Security + MyBatis + Thymeleaf + Layui  
# 二、本地部署   
  
1.将项目文件下载到本地  
```
git clone https://github.com/whgojp/JavaSecLab.git
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwMmxiaOAia6Cfo0xia3F8ZFfVsAPQ1nSvsYLORWn45gCCBibxQOMTenyFrg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
2.创建数据库导入sql  
  
在本地创建javaseclab创建并导入数据库文件  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwHicXjByG9IL3upficswNgaamMgGbxzB5jlxPpLVDJia3eIQN0HSib04Ggg/640?wx_fmt=jpeg&from=appmsg "")  
  
3.idea运行项目  
  
使用idea打开项目文件   编辑 application.yml docker改成dev   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwUUh4zibzPoQMqgnL4qJGErnian09x1LpkeHlia4euAtrm6qVXEaApyRjQ/640?wx_fmt=jpeg&from=appmsg "")  
  
编辑 application-dev.yml 的数据库账号和密码还有端口  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwWibWl0hdwOmWt5Q54cSVee3hYjLicezqsO37m8ke6Y0oMFN64KKj2yWw/640?wx_fmt=jpeg&from=appmsg "")  
  
等依赖下载完成后  运行项目正常 没有报错说明  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwIZJel9fXTK7GnvicTA38nKfX7BOtSZweornNyIPcq4icZXTQNmuZWGTw/640?wx_fmt=jpeg&from=appmsg "")  
  
访问80端口   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwPn2iabrNBGT5CIAiaPNRicmibnkh3wnKf3DZibha1BbQY2Wyj93H959UH6w/640?wx_fmt=jpeg&from=appmsg "")  
  
输入账号和密码 admin/admin即可  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwmZoOmRsMUXLJs7QKTA378JibSick1sIkneyeOHaVYMloJICfYXicwT4xA/640?wx_fmt=jpeg&from=appmsg "")  
  
参考   
https://github.com/whgojp/JavaSecLab  
  
  
想系统学习渗透测试？扫码报名培训课程！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Jvbbfg0s6ABQhUyBWAEv8bZuIiaJf1ucwugEU8DptJpszyE6jUaEdz4Ok09ia1xmY3QWQgDE95stpS0qbdAn32rg/640?wx_fmt=png&from=appmsg "")  
  
  
