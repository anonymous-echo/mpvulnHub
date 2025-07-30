#  Java代码审计 || 通过某博客系统实战学习一个有趣的 SSRF 漏洞分析   
 实战安全研究   2025-02-12 01:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/FFcgFn6WVc2ribkEhzXXbiaAE31xwNoCLjKDDibq9HkTiab5BllP8wbSSabd7CIoJSLfHQHjq6ZBf0CoVJaEdKgibNA/640?wx_fmt=gif&from=appmsg "")  
  
嗨，大家好，这里是闪石星曜CyberSecurity。  
  
我是你们的老朋友润霖。  
  
今天通过 Halo 博客系统给大家讲讲在 JavaWeb 中 SSRF 漏洞分析。  
  
如果大家想系统入门学习 Java代码审计，欢迎报名我的课程，五十多节课，平均一小时，20+企业级实战项目，低至499，详细可点击下方链接查看。  
  
[《Java代码审计零基础入门到项目实战》2025年第一期招生即将结束，低至499，五十多节课，多重福利来袭！](https://mp.weixin.qq.com/s?__biz=Mzg3MDU1MjgwNA==&mid=2247487190&idx=1&sn=704ae787b03a1066720f28cecdc33545&scene=21#wechat_redirect)  
  
# 一、项目简介  
  
**Halo**  
 [ˈheɪloʊ]，意为光环。当然，你也可以当成拼音读(哈喽)。  
  
轻快，简洁，功能强大，使用 Java 开发的博客系统。  
  
Halo 的诞生离不开下面这些项目：  
- Spring Boot  
：Spring 的快速开发框架  
  
- Freemarker  
：模板引擎，使页面静态化  
  
- H2 Database  
：嵌入式数据库，无需安装  
  
- Spring-data-jpa  
：不需要写 sql 语句的持久层框架  
  
- Ehcache  
：缓存框架  
  
- Lombok  
：让代码更简洁  
  
- 等等......  
  
# 二、项目搭建  
## 1、环境要求  
  
以下是我的测试环境版本详情，除 JDK 需要以下指定版本外，其他仅供参考。  
  
<table></table><table><caption></caption><colgroup></colgroup></table><table></table><table><caption></caption><colgroup><col/><col/></colgroup><thead><tr style="box-sizing: border-box;"><th valign="top" style="box-sizing: border-box;"><span cid="n56" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">软件名称</span></span></span></th><th valign="top" style="box-sizing: border-box;"><span cid="n57" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">版本</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td valign="top" style="box-sizing: border-box;"><span cid="n59" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">操作系统</span></span></span></td><td valign="top" style="box-sizing: border-box;"><span cid="n60" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Windows10</span></span></span></td></tr><tr style="box-sizing: border-box;"><td valign="top" style="box-sizing: border-box;"><span cid="n62" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Java</span></span></span></td><td valign="top" style="box-sizing: border-box;"><span cid="n63" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">JDK1.8_161（</span></span><span md-inline="url" spellcheck="false" style="box-sizing: border-box;"><span leaf="">https://www.oracle.com/co/java/technologies/javase/javase8-archive-downloads.html</span></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">，往下滑）</span></span></span></td></tr><tr style="box-sizing: border-box;"><td valign="top" style="box-sizing: border-box;"><span cid="n65" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Maven</span></span></span></td><td valign="top" style="box-sizing: border-box;"><span cid="n66" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">3.6.3</span></span></span></td></tr><tr style="box-sizing: border-box;"><td valign="top" style="box-sizing: border-box;"><span cid="n68" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">IDEA</span></span></span></td><td valign="top" style="box-sizing: border-box;"><span cid="n69" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">2024.x</span></span></span></td></tr></tbody></table>## 2、项目部署流程  
  
源码下载地址：  
```
https://github.com/halo-dev/halo/releases/tag/v0.4.3
```  
  
下载完成后解压项目文件，使用 IDEA 以 Maven 方式打开该项目即可，会自动加载相关依赖。  
  
该系统使用了 H2 Database 作为数据库，则不需要像 Mysql 那般操作。  
  
进入  
src/main/java/cc/ryanc/halo/Application.java  
代码中启动项目即可，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaq09VMEcrVDjBDLMv5M5yqz3xtJz129YXAIoRG2cyCVXiaxUO8I4Trjw/640?wx_fmt=jpeg&from=appmsg "")  
  
访问上述提供的地址  
http://localhost:8090  
，进入安装向导，内容自行填写即可（备注：电子邮箱一定填写自己可以登录的，后面测试会用到），如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmria7ju1XafAwvl4bvrIk2PK83FhCgnqGw3wqhVEOiaEwAfgFnkmUVl4N4A/640?wx_fmt=jpeg&from=appmsg "")  
  
最后成功安装后可按以下地址进行访问：  
  
前台地址：  
http://localhost:8090/  
  
后台地址：  
http://localhost:8090/admin/login  
  
备注：  
- 如果遇见报错，也许是因为依赖没有成功下载或加载，可尝试退出 IDEA 后重新进入，如依旧不能解决可将问题详细整理后在群里咨询。  
  
- 如果你的系统内有多个 JDK 版本，记得在  
文件 - 项目结构  
（英文版 IDEA 看图寻找吧）将 JDK 版本设置为 JDK1.8_161，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaRicsWuLIGiaSk4lNp58iaKUp41zkaQXFIGO03Hh3WwrdmhPja6s3lCSGQ/640?wx_fmt=jpeg&from=appmsg "")  
### 三、SSRF 漏洞代码审计  
  
正向梳理功能时，发现系统内安装主题处，可通过远程拉去的方式下载主题，可能会存在 SSRF 漏洞，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriacMoHJvFVnF5r594wxMSXP01ZeNQsS3iaTTDoSex17XpzGLyaB65UrDA/640?wx_fmt=jpeg&from=appmsg "")  
  
通过抓包获取到接口名为  
/admin/themes/clone  
，通过关键字逐一尝试，最终使用关键字  
/clone  
定位到该接口的 Controller 层代码为 ThemeController，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriau6cJQNAYEg97UWjpbWDOImwiaMV33QlmsqbHmDGHnwOMHKAoLU9jofA/640?wx_fmt=jpeg&from=appmsg "")  
  
点击进入 ThemeController 层，具体代码位于第 180 行至第 201 行，如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaRw6JwojFv2KUJsqAOU7wlK1HAvh1dx9xWdhG0PIrlazmvlNKdMAhSw/640?wx_fmt=jpeg&from=appmsg "")  
  
下面进行代码审计分析。  
  
①、第一步，单击 remoteAddr 查看传递调用关系，在第 186 行处进行了 isBlank 判空操作，没什么其他值得注意的。然后就直接到第 190 行，进行了 git clone 拼接传入的 remoteAddr 参数操作，使用的是 RuntimeUtil.execForStr 方法执行命令，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaY4hehd5WLsAVmLvUs4CSw5zTa3LgumjiaSibYwpGNzy6KBRIS4pUMEvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
②、第二步，分析 RuntimeUtil.execForStr 方法。Ctrl加鼠标左键点击 execForStr，进入该方法，发现该方法是 Hutool 组件下的工具类，其中底层就是使用的 ProcessBuilder 执行的命令，没什么其他额外需要注意的代码，可自行分析。如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaK8W00ck3D5mibE54ia8pXHebZLtwt6RNzxVUdxeKRic7hbiaGstXDYaic7w/640?wx_fmt=jpeg&from=appmsg "")  
  
③、第三步，总结来说，底层使用 ProcessBuilder 执行了 git clone 拼接 remoteAddr 的命令，其中 remoteAddr 我们可控，进而通过 git clone 可以进行了网络请求操作，导致触发 SSRF 漏洞。简单说就是 ProcessBuilder 命令执行加上 git clone 触发的 SSRF 漏洞。    
  
最后，在第 190 行设置一个断点，内容如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaDZcDHVVjY8ic3ntXPaNbhhyLfNNCibaZMhZEy4V0XbYIy0md1LxpbRwg/640?wx_fmt=jpeg&from=appmsg "")  
  
这么看来不仅存在 SSRF 漏洞，还可能存在远程命令执行漏洞。  
## 四、SSRF 漏洞验证  
  
访问外观 - 主题 - 主题安装的远程拉取功能，键入远程地址和主题名称，点击安装，抓取数据包如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaUQf5A4bS5ESGHLGtHX01NPPfic3xaIMrlO42MFraQelypCIJHrQzYOQ/640?wx_fmt=jpeg&from=appmsg "")  
  
访问 DNSLog 地址，可以看到存在探测行为，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaD94Pu6vcicWdreYZs0s83MUMA20bRHo3WRcVSlDwaW5c3HFN5iaQLlJA/640?wx_fmt=jpeg&from=appmsg "")  
  
下面探测内网端口开放情况。  
  
我开启了 8080，7089 这两个端口，可以通过响应时长判断出端口开放情况，如果端口开放响应时间很短，如果端口未开放则响应时间边长。  
  
端口开放情况探测，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaMVbk1py1FYdZKS6TVSy9UR3sgNGAg0IHvA0aHmuia1GqZSyVGFztA4A/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaMlC8raLPdExAVeIFjhoWylGsbyn9ZPv60z2vM5wsRibQMm214PgYqEw/640?wx_fmt=jpeg&from=appmsg "")  
  
端口关闭情况探测，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaUtO0bRYYFV5icNJeMKhQMiaNiaibLH5Zlg4IPwIKrAFaGuybzA8IFIzjPA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc0YAVzeykIhNJFaHRSTrmriaJbCYXaQu8YhCBYx1BhibSA6kYslx72neFrOnHLw779ib3WkwRt4wtHQA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
