#  黑盒乱锤某专属SRC到0day代码分析   
 不秃头的安全   2024-12-13 09:54  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVNCXqrL9k0r2icauIbCEBEls8X0kfM78frUZBL3ZSZKZlICQlev704WAdTLlWPZ0taFhvEm1mr3Lg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******黑盒乱锤某专属SRC到0day代码分析******  
  
  
  
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。  
  
还在学怎么挖通用漏洞和src吗？快来加入星球  
-考证请加联系vx咨询  
  
由  
于微信公众号推送机制改变了，快来  
星标  
不再迷路，谢谢大家！  
  
  
****  
**上次有小伙伴说JAVA利用链分析太枯燥了，想看SRC和代码审计的案例。**  
  
**于是～作者日思夜想，翻出了两年前的历史案例，终于写出了这篇文章。该案例历史久远，资产早已下架，仅供参考学习。**  
  
**这个作者真是太用心了，点点关注吧！！！**  
  
**-------------------------------------------------------------------------------**  
  
**故事开始： 两年前的一天，我在群里看着大家吹水，又有人挖了几个“w”。屏幕上一个个喜报跳出来，让我心里五味杂陈——既羡慕，又失落。羡慕的是他们的技术实力，失落的是自己与他们的差距。那一刻，我下定决心：一定要达到群友实力的一半，哪怕只是一半也好。于是，我摒弃杂念，用一晚上的时间埋头钻研，终于有了以下这篇记录文章。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicayU6CuDqbFgiaxJY3enyUl1ibUwb0QP5M7lWJwj67Y9SCCVQ5mh8Xrxg/640?wx_fmt=other&from=appmsg "")  
  
**该专属SRC目标为教育资产，对于常年打edusrc的小伙伴来说会很熟悉。**  
### 一、信息收集  
#### 1.1、学号收集  
  
确认资产后，作者比较喜欢收集一些信息，例如：学号、工号、姓名、手机号等等。  
  
通过google信息收集得到学号。  
```
https://www.xxx.edu.cn/info/xxx/xxx.htm
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic3O2oD0wLFLBnY4HIrgQ2qwTEKOpic40ToSzJ3QgEbmiciaDZs5kBUicO0w/640?wx_fmt=png&from=appmsg "")  
  
在搜索引擎查看子域名，发现存在一个信息系统平台，并且没有验证码。  
  
根据提示测试，存在弱口令。  
```
用户：2020xxxxxxxx 密码：2020xxxxxxxx
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicbQQiboP0GEAC9iaAhuMPrRNzTQ5SOibOm3A3Nic7twJeSxXmwZgu41csOQ/640?wx_fmt=png&from=appmsg "")  
  
登录成功后，翻找功能点，在我的团队->新增功能点处，发现大量学号、姓名信息泄露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLickJZQndBic0SBs8hriaH6EpmY0RWTyfCQSeb79PF0PrIduCyicPOWukBmw/640?wx_fmt=png&from=appmsg "")  
#### 1.2、寻找初始密码平台  
  
google搜索关键字：“初始密码”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic0f8Cgj6wd1StKI721yqe87p2kfnBNAGNps6N1PCZ2CEmD6h58SAdZw/640?wx_fmt=png&from=appmsg "")  
  
使用学号：2020xxxxxxxx，密码：666666，即可成功登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicFRRKiafVhhkmyUyvpb00xX0dGwZe0tSvZq2oKpFvabVwwsicCY1nxoJw/640?wx_fmt=png&from=appmsg "")  
  
在查看个人信息处发现泄露大量敏感信息，其中包括学号、工号、姓名、sfz等等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicpG2UZo7czzLicKsD4WokHEFB0o5PdBDVyZPQZbsickQldC7xtbfO8kTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLickV9QRVKcjpOcUA9WYu5V9pHk9O3TEOVlOqTfwTAXrtNOJX1xLibSsjA/640?wx_fmt=png&from=appmsg "")  
### 二、登录网上服务大厅  
  
根据统一身份认证系统的提示，密码默认为sfz后6位。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicz0r895vRJoYyH7dmsrpRmUibQom4yKY5D0BotuP2VRrrxOP2asic4TWw/640?wx_fmt=png&from=appmsg "")  
  
**登录服务大厅后，里面存在诸多系统提供我们测试。**  
#### 2.1、某某咨询系统  
##### 2.1.1、越权1  
  
点击体检中心。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicrIEaBEib5IIiaAQSFjQVA8fS3EricHbKgRpIFd1XbEbbNndiaRw4H5DeXA/640?wx_fmt=png&from=appmsg "")  
  
查看流量包，把该接口所有的参数全部删除！（滞空大法）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicJIcpmicicFsGt1oUbBAYZ3IgicaRsSaLUD4ndYcA12ulC29bZZsQqWbwA/640?wx_fmt=png&from=appmsg "")  
  
拿到大量用户的 userid 值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic3LvC3aSteVnJvKKvKGeO6hLiaoCcvsrLslD21fzkCQ5xx7bpXt4u8cQ/640?wx_fmt=png&from=appmsg "")  
  
点击修改密码，继续抓包数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicwib0eerjBB7q9xIvoAnAc1icyQc7EuuBDX5DLamGdRMPL6FoMM2rricTA/640?wx_fmt=png&from=appmsg "")  
  
把 userid 值替换为 getById 后面的参数值即可越权成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicBwPuGeGuqF3QCZ0V6Jmy94aS0TM7j3tMaG6vBBNGHtDVnnbsQ3wCeQ/640?wx_fmt=png&from=appmsg "")  
##### 2.1.2、越权2  
  
点击个人中心。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicIRNjNSq2vhC02K4WUxicxwVJnfQSgaozjhodEgxLxpqq6Licv5DQaHhw/640?wx_fmt=png&from=appmsg "")  
  
修改 userid 再次越权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic5JEIvxWBkqLdTgXurxVsJrE1V8LNXPy8Wql6FLpCY9w52Fo5YZGCzA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicNhuNzC685G9icKj1WLjlrLRgcUBDyAiaaWLC32iceUqdAnnml0brUdTXQ/640?wx_fmt=png&from=appmsg "")  
##### 2.1.3、信息泄露  
  
在路径：https://xxx.edu.cn/serverapi/swagger-ui.html 中泄露后台api文档，接口中存在大量高危泄露信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic5BeDjhN4yD1AucBHa1Uuvy4TPeMyVQCpn8v6xqewCydAwicfd82bySw/640?wx_fmt=png&from=appmsg "")  
  
/serverapi/staff/getStaffList 接口泄露大量教师敏感信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicueOCicDH9jMEXK2SCYF1tiajtBav038KE0q25LzuFtW3ia1QGcchBjcaQ/640?wx_fmt=png&from=appmsg "")  
  
/serverapi/api/core/user/page 接口泄露大量教师及学生敏感信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLica7b9e7UjribtEW1ibbkHjvicrkH5eXDxYpficZ6nygC8icLA5gt0yHaarZw/640?wx_fmt=png&from=appmsg "")  
  
/serverapi/student/getStudentList 接口泄露大量学生敏感信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicECCPpeibRR4f92Z5MQtFRic6YSaj7PB52A7hjtdj9iciaWVloLgpoxEkbA/640?wx_fmt=png&from=appmsg "")  
#### 2.2、某某一体化服务平台  
##### 2.2.1、弱口令  
  
**该系统存在多个弱口令账号密码。**  
  
**使用默认密码获得超管权限，接管某某一体化服务平台。**  
  
学生基本信息查看点击查询，可以看到全校敏感信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicic3gcfFpxCjATOehib0nKG8jAj8bQ4piaicAHYkgqwWjuNGTOiaJTXiaec6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLica0EoxVoxm4KEUoWH65QNtg5op8Nu2qjAt0gfPZYkOjOYuPBebRUhEg/640?wx_fmt=png&from=appmsg "")  
  
大量敏感数据，不过多展示。  
##### 2.2.2、越权  
  
使用学生账号登录系统，在学籍卡片处点击毕业证书查询可跳转到报表系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicOhpSRD2saoBEicicJqzZSQyZYT402KflCej2GlgE5yXJpgJZXfAW8vcg/640?wx_fmt=png&from=appmsg "")  
  
修改参数 xs0101id 为其他学号可查看他人毕业证书。  
```
https://xxx.edu.cn/ReportServer?reportlet=/BYZS.cpt&xs0101id=202xxxxxxxxx
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic1Wbg469ichQibibMVkj6ibpRPfnhzWbvLfCh8PQ5cGicSa71YJXSMIKFRSg/640?wx_fmt=png&from=appmsg "")  
  
学位证同样。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicQ3Rf4LWf3z0pGc7v71LrbtF9305ObAleCNIfvwBqE3vicCTyfTfYJDA/640?wx_fmt=png&from=appmsg "")  
#### 2.3、某软服务平台  
  
将上面获取毕业证、学位证链接中的 reportlet 参数值删除或修改，可得到某软服务的后台地址。（可再次使用滞空大法）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicy2IaoD4XKSQ7FEFrCqDBJMjUribTAnCJml2Oic0gbx8RnGJNpFK8jQSg/640?wx_fmt=png&from=appmsg "")  
##### 2.3.1、弱口令  
```
admin\admin123
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic92B1k4Sengicxn9iaO4VUNUA10vPIVtjfBmA8buRVDmVN4ahLpMFMv7A/640?wx_fmt=png&from=appmsg "")  
  
登录成功，查看用户管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicibB6HK4yiaibZlbE1gKU1pKv0gOHFmhHcC31F7f26ryMdTyJ07t194PVA/640?wx_fmt=png&from=appmsg "")  
  
查看数据库 ip 及账号密码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLiclb653ibMkDhcNiaHvvS9ZmNQ9Mz2p7zaQtMJAez8EuXrZ7teoeFAkjAg/640?wx_fmt=png&from=appmsg "")  
#### 2.4、某某校园自助服务系统  
##### 2.4.1、弱口令  
  
验证码可重复使用，通过暴力破解得到大量弱口令。  
  
弱口令密码规则如下：  
```
（姓名拼音）\123465 （工号）\123456 （学号）\（sfz后6位）
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicXtou6H5YFkHc7Tib6jW5icfkuyQeoNODgwzbMrHiac6JRjDsDd3QiaGkpg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicEOltDGuDHB1YDn2riaib4OeL3KVOpXESZ6SN1VGRbVQdYy6YaLYicCh0A/640?wx_fmt=png&from=appmsg "")  
  
弱口令较多，不过多展示。  
##### 2.4.2、ssrf  
  
将数据包转发到Burp，复制Burp Collaborator Client中的域名链接，发送如下请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicAFCZFavMkZ7uIicyJNPI8XeT4QV8vZdBtcWibmzibJAYAtPGNzF1icMOcQ/640?wx_fmt=png&from=appmsg "")  
  
得到回显。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicz6xfLj7ibmibfGPGvm2RUknaVUpQDwsKTO3X9Kwopgz3tywicibS7yicxfA/640?wx_fmt=png&from=appmsg "")  
#### 2.5、某某服务网络云平台  
##### 2.5.1、弱口令  
```
（工号）\123456
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicB2ml5weyzwibTxWIhLYlAKia7bbPjutgbaWc4o3MaZUXF7qu4DBAh5Fw/640?wx_fmt=png&from=appmsg "")  
  
大量学生敏感信息数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicrlJmibHSv4lPBQ5LCNic54DBU6WLLOE60rUAcicADyW2nOF4QlibzzdVyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic4JOiagOm7GVYO480BTbzH453ATNICAc0I1qmycugUOpYbfSib8yR7RQg/640?wx_fmt=png&from=appmsg "")  
#### 2.6、某某资源库  
##### 2.6.1、未授权  
  
通过 js 代码发现接口 /user/getUserInfo，拼接得到如下url：  
```
http://xxx.edu.cn/api/as/user/getUserInfo
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicI7tg965G45VdA3r6s350H8pgyDBHUibBLK1KjKTdM3Hbic12R0kqDrzg/640?wx_fmt=png&from=appmsg "")  
  
直接访问发现存在账号：anonymous，密码为MD5加密解密后得到：Aa123456。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicdoErngDlkoSNphpGnAP3KpHVjJdEOQj8cMhN5xlfx8Go3PMMc9ia57g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicuXe1W4icncCCY75zdkeKADibLmXkeUJpPwuuyFUiaQKceEhFe1ZdSVbtw/640?wx_fmt=png&from=appmsg "")  
##### 2.6.2、越权1  
  
成功登录游客账号。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLict2d8hD1JpdT3BibO0AHrHe5vYZicayziaCY5Uib2XhFSDZZRaGuIicibAh8A/640?wx_fmt=png&from=appmsg "")  
  
继续翻找 js 文件，发现 /user/listAllGroupUser 接口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicCahYkv3PaBEpXLEWsEfbLYACqsDfq45UIkewn98OelYWgdoMTskudQ/640?wx_fmt=png&from=appmsg "")  
  
通过上面的未授权接口 /user/getUserInfo 获取到 groupId 的参数值。  
```
{"groupId":"default_group"}
```  
  
既然存在那么简单的未授权漏洞，那么越权漏洞一般必然存在，列出组中所有用户。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicMrBMztXrNoPwJla4KLHLTFIZTSMQkVlyEDsiaBvpqNxHFLoGmib6sNkQ/640?wx_fmt=png&from=appmsg "")  
  
通过上方接口 listAllGroupUser 得到的用户名：160029 ，密码和 anonymous 用户一样：Aa123456，可登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicAVo0bTppF5Z2sXbAPSZiaicaxanqrItgP1CenB6pLichCIW4kIyqcEVcg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicOuibQBg4GwR7Z7p3gpibs0hI0oD8d0RDEaWB818DpUzvRBw8yVsmIzVg/640?wx_fmt=png&from=appmsg "")  
##### 2.6.3、信息泄露  
  
通过点击该账号页面中显示的文件，Burp抓包拦截。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicS7mMiaJ9a8I6LDsw986benOIuBbUSJvEeW2rsB7VCGkAo9sIgOmEJtA/640?wx_fmt=png&from=appmsg "")  
  
注意拦截漏洞url为：http://xxx.edu.cn/api/as/file/recommendFileNew。  
```
POST参数：{"fileId":"xxxxx.jpg"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicFiaaO7sANp1ntLD4cZRarTDwfus096FX9A0Uhpia3638rIPGKfaeG4ibA/640?wx_fmt=png&from=appmsg "")  
  
该接口泄露了管理员密码为MD5加密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLichFVLICwSbR1VYyWkpRhZ7TKChcTtSG2mgFVL5OJSp28aAF7HrY4qNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicSmfibkNMvlhMeavPdnFEv1EVHSl7hITmHOxibFKheKnOYcBP3QPmQ5yg/640?wx_fmt=png&from=appmsg "")  
  
通过管理员用户成功登录，具备众多资源库的管理权限和大量文档。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicicKhxla33dia0kTETckxahuHOdgOFGbuvxlUUibGnRJ2t2od03yOYoxNw/640?wx_fmt=png&from=appmsg "")  
##### 2.6.4、越权2  
  
通过admin用户打开毕业生作品，拦截数据包得到 fileId: xxx.jpg。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicicPuVhJpP7nIibZqq9VX63Sib3rwiba89kSMotlaGdjAkP5n0Ljz1ElA4A/640?wx_fmt=png&from=appmsg "")  
  
通过 /api/as/share/listMy 接口可以看到所有的文件fileid值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLiciajiakZcUcBISsrAtcGR4UBib9gwVT6TnJ6oscibKYeXPe2Mvaczwdey8g/640?wx_fmt=png&from=appmsg "")  
  
遍历读取，可读到敏感文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicaIQFUrhdsOwCF4Y9fDS37rVAWfib1VATlvOuku8X1ibdiatRRMHlibNYGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic25oJdEfmgibJQZjLiaPhsictNaAIKyyBCWklR1JBRA7U3WHGqDDbLqHpg/640?wx_fmt=png&from=appmsg "")  
#### 2.7、某某登录系统  
##### 2.7.1、签名伪造信息泄露1  
  
点击忘记密码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicJcggQT2xqNe9Z2ryW78VxqZDZgQ8JtEZuWJ4HH7VvuTDYmsCxP2Zpg/640?wx_fmt=png&from=appmsg "")  
  
输入账号12345，开启Burp拦截数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicMH4qNalfkwO60WFl4dpn9HrBX5T4SWCRHPse1cCBsmtKNdASeICwjg/640?wx_fmt=png&from=appmsg "")  
  
返回用户ID为：12345 的敏感信息，包含sfz、姓名、学号、班级。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicOrpQEAqpmXbUmOhbNAc9JsYWvmRJgl0ue2wCzkzrlZfgymTfqFl04A/640?wx_fmt=png&from=appmsg "")  
  
通过前端js代码发现参数Sign的生成规律。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicfA4AdUhWxOMibibkV4aSCuHvYibWO9bCA0icId91ZIMlCVeycOORUJKoaA/640?wx_fmt=png&from=appmsg "")  
  
其中 MD5KeyYm 为 ok15we1@oid8x5afd@。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic6zXqz5S67O3y6fvcedaN9Pv5NJcVHalOPxGOIrLBjkuXTbP2fQKahA/640?wx_fmt=png&from=appmsg "")  
  
编写python脚本（代码见末尾）加密生成Sign，并遍历参数IDNo，第10000到第10100个，python脚本逻辑如下：  
```
因参数Sign是使用IDNo与参数IDType的值，当前时间加上前端env.js泄露的Md5Key的值一起MD5加密的，所以遍历IDNo参数（从10000 - 10100），加密后以POST方式发送到漏洞URL：https://xxx.edu.cn/QueryAccInfoH.aspx 其中得到的Sign值就是：{IDNo}|{IDType}|{当前时间}|{Md5Key} 加密后的值，如ID为12222，当前时间为20220627124630，带入就得到：12222|1|20220627124630|ok15we1@oid8x5afd@ ，将该值MD5加密后就得到Sign：6287fd7b29d7942cbe6c7f48f7451097
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicpUMwohmz0F24I7Oc1pWEoibPzSog44wDRdrTicnGtzGntsg0coNuYX5Q/640?wx_fmt=png&from=appmsg "")  
  
遍历数据如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicl5ics1yBa1ujpNU1icJvvqxp0K3svt4J5U0rOoGKPslCfPaVkYEoFoyg/640?wx_fmt=png&from=appmsg "")  
##### 2.7.2、签名伪造信息泄露2  
  
/QueryAccPhoto.aspx 接口带上签名可遍历用户照片。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic4MJLqugczSXDGVhPkiaJuSTIobRyYQWG6EYkPk6fibmOLJ9EFYtPwqSQ/640?wx_fmt=png&from=appmsg "")  
  
照片这里不过多展示。  
#### 2.8、某某服务信息平台  
##### 2.8.1、弱口令  
```
（学号）\（学号）
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicQpBicic5vstwYEXBnZZrzI3m0iadA1kZRYGdMiaQ1Bpf4ibGuMfibBXjamPg/640?wx_fmt=png&from=appmsg "")  
  
弱口令登录成功后，在选择项目经理功能点处存在信息泄露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicrPw6qTxF7iaichFqIssyAa5hSFBxMKYOicfOfH4TePebm80IyM4pAvWsg/640?wx_fmt=png&from=appmsg "")  
  
泄露邮箱、密码等信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicV96NleDgWEqXkWUkf58oYch8RPvRW8oxpPsT22Ps1TiajicuW9g7AibZQ/640?wx_fmt=png&from=appmsg "")  
  
密码 md5 解密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLichxhNWWicZ6fMdwMR2cj1ibJjkwZg1kGmqKHiclPWYxmFibEdukwk7CVBicA/640?wx_fmt=png&from=appmsg "")  
#### 2.9、电子邮件系统  
##### 2.9.1、密码复用  
  
重复使用上面的邮箱账号和密码，可登录电子邮件系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicTstMG7cljibdsxpibCv8zs7jMQELphrYWURV5pBfGph8iaOHEticiaBZodg/640?wx_fmt=png&from=appmsg "")  
  
接管邮箱。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic8ppTDiaDx5aljNE22oIjBu7WN9XzNulGJJZ4e45eYKKgeXMkTsgOmiaA/640?wx_fmt=png&from=appmsg "")  
#### 2.10、宏景人力资源系统  
##### 2.10.1、0day前台注入（新版本已修复）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicMQribIvPBbKQOTBVMl6gY0HHqveJbgMlyFnYfXHdMb0GAiczick69pGkg/640?wx_fmt=png&from=appmsg "")  
###### 2.10.1.1、权限绕过接口1  
  
打开 F12 翻找 js 文件中的接口进行测试。  
  
在文件在发现一个接口，路径为：  
```
/hire/employNetPortal/search_zp_position.do?br_getpassword=get`dbname="+dbName+"`userC="+userNameCloumn+"`passC="+passWordCloumn 其中 “ ` ”表示GET请求中添加参数的“ & ”。
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic8YlV2xJ0d2Fq1MskOgTMk8I6R615FuC4t00reg5OZqm6jDysKjOabg/640?wx_fmt=png&from=appmsg "")  
  
访问该页面，通过在找回密码页面JS代码中得到路径：  
```
/hire/employNetPortal/search_zp_position.do?b_query=link
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicsSpGEibbaichBsed73A0BoyGKtWGnQ4hFHs3L6hoTKHaolFnlO0MicBwA/640?wx_fmt=png&from=appmsg "")  
  
**拼接访问后可以进入系统页面，此时已经通过身份验证，猜测后台已将当前请求Cookie设为通过验证，再次访问漏洞URL发现不跳转回登录页面，绕过了登录验证。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicibiaQFI9zPYkqyd58c48icmoicCqRyZZ1jQDxKUyYNuo99Qt1eYXorPLSQ/640?wx_fmt=png&from=appmsg "")  
###### 2.10.1.2、权限绕过SQL注入  
  
在 js 文件中继续翻找，尝试寻找后台的链接。  
```
/train/plan/searchCreatPlanList.do?b_selectPlan=query`selectID=
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicL91gu8IJZ2rMpe7aNGjbF0FwThKvZKXuYAlBdxIrJ15OOuMglUibrFQ/640?wx_fmt=png&from=appmsg "")  
  
这时重新访问漏洞URL，发现已经可以访问，绕过了验证。  
```
http://xxx.edu.cn/train/plan/searchCreatPlanList.do?b_selectPlan=query&selectID=1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicdHN5UcGV5CFyBKetR8gwrfQzTSfh4fE1fdEH6SibyFFTfaXIhKdLDog/640?wx_fmt=png&from=appmsg "")  
  
参数 selectID 输入单引号发现报错。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicI1VAeXJAKqic9yEib2B4JlCrZlr8YwicxWKklmRRbCEQlunJ5n3QhVPog/640?wx_fmt=png&from=appmsg "")  
  
脏数据绕过 WAF，查询数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicdxdh7m6D51gJmfBBVq851cBCrc1yVb7nIZ5KkdlBtjvOOtPZqWHCyg/640?wx_fmt=png&from=appmsg "")  
  
**如果直接访问该注入点会自动跳转到登录页面。**  
###### 2.10.1.3、权限绕过接口2  
  
回到登录页面，打卡 F12 发现忘记密码的功能点，它的 onclick 调用的是 getPassword 方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic7JKmE14wcHXWpm9CLaibiaicak0WNHT2crbARBYicvpP8zic4DNeByLTnfg/640?wx_fmt=png&from=appmsg "")  
  
点击忘记密码链接，看见这个忘记密码的 jsp 文件和登录主页的 jsp 文件，不仅陷入沉思，这是一个 templates 模板的文件夹，下面应该全是 jsp 文件，那么会不会存在 getPassword.jsp 文件呢？？？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicnibB3Y3UmfqaQNWXs3cAghlTx3iaXMw3hIUd648M7Dd8as3qvfPeqtlg/640?wx_fmt=png&from=appmsg "")  
  
拼接链接，回车访问！！！  
  
网页不存在......  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLiciaPN8ogBbMx2AnVWiaM2C1ad1XFyG2t0xHL2EIyHJJ77qTBoTXB8Oamg/640?wx_fmt=png&from=appmsg "")  
  
全部改成小写，回车成功访问。  
```
/templates/index/getpassword.jsp
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicD27rCDKm4asoFIaoszk5DDeGMWAl3zSVHpVyCAKu0z8XtL2Pn8ohng/640?wx_fmt=png&from=appmsg "")  
  
访问后台注入点，没问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicegibretichCeJPB7cI2xC76GjiafFKNntGSaInvmIrteus6uk0jK2OQLQ/640?wx_fmt=png&from=appmsg "")  
### 三、宏景前台注入0day代码分析（新版本已修复）  
  
针对上文提到的宏景前台SQL注入漏洞，作者对其运行逻辑充满好奇。为了解其背后的实现机制，接下来我们将深入代码进行详细分析。  
#### 3.1、SetSelectedRecordTrans注入分析  
```
1.访问以下链接即可绕过登录直接访问后台sql注入点 /templates/index/getpassword.jsp 2.后台sql注入链接（selectID存在注入） /train/plan/searchCreatPlanList.do?b_selectPlan=query&selectID=1
```  
##### 3.1.1、/templates/index/getpassword.jsp 分析  
  
16行 session 设置 islogon 为 true ，也就是说只要访问这个文件就会给我们设置 session。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicI7k6micduOOVgibib3d396rw0pHGSS09RNlrc4ySSYWVm6wsekJAyCJgQ/640?wx_fmt=png&from=appmsg "")  
##### 3.1.2、注入点分析  
###### 3.1.2.1、struts-config.xml  
  
查看struts-config.xml文件，找到/train/plan/searchCreatPlanList路径，跟入com.hrms.struts.action.FrameAction类型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicgv0h99naruDIHxXuDbUnrn26BLtG27icYfxnicgl0xMGSxibbZpaq71vA/640?wx_fmt=png&from=appmsg "")  
###### 3.1.2.2、ActionBase类  
  
FrameAction类继承了ActionBase类。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicyZicYdryYrJuhUDeUhoWzSmwTQzNJwm9PALYzE4fIRVEwyQrG0x4AMw/640?wx_fmt=png&from=appmsg "")  
  
跟入ActionBase类，找到 execute 方法，该类会默认调用这个方法。  
  
126行获取session，任何128行判断是否为空，因为我们之前已经被设置过session了，无需里面上面的代码，直接走到最后 myexecuteIt方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicUib4EXh7JBJnlicHLsR3ChgGdCNkIDodHDn1I1wTlemJEbOoxNegR9ibw/640?wx_fmt=png&from=appmsg "")  
###### 3.1.2.3、FrameAction类  
  
myexecuteIt方法在FrameAction类中。  
  
83行获取了session进行下面的判断，我们不为空，所以不必理会。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicCFUVicPvutf7kEoWIMlkjUF6ojTMRfVLd2rqaiatju5CKCKhicX8Yj4ibw/640?wx_fmt=png&from=appmsg "")  
  
94行获取session的sessionHM值，我们没有这个值，进入96行创建一个hashmap对象。  
  
再在100行中把session的sessionHM为空的值放入var5（类似hashmap）里的sessionHM key的值中。  
  
103行获取var5 requestPamaHM key的值，我们也没有这个东西，所以var13赋值也是为空。  
  
115行把var3（Request请求）和空的var13带入到A方法当中。  
  
117行最后返回的对象put添加到requestPamaHM key值里。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicib7LRzwI7EoIltD9TR2icDH6hO8gwnF8ia1BrMhqnUDb12AogzjuAambA/640?wx_fmt=png&from=appmsg "")  
  
52行获取所有的参数名和参数值。  
  
53行进入B方法。  
  
55、56行，如果var2为空，就创建一个hashmap。  
  
61行以&符号进行切割，然后63行对每个参数名和参数值进行遍历。  
  
64行去掉空格，65行再以=符号分割，分别获取参数名和参数值。  
  
68行加入到var2 hashmap返回。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicTbxQwWtmx95pnibR8Lgq2Lic6U95ZEpJ7icr0VLQvZx0ObKVkuHkfcia1g/640?wx_fmt=png&from=appmsg "")  
  
跟进B方法，可以看到是一个全局过滤方法，单双引号都被过滤掉了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicvniafkqscHWZcJoflczRdDJHia8foic9IWwRkt41KPiafKN4MherU1ws0Q/640?wx_fmt=png&from=appmsg "")  
  
再次回到myexecuteIt方法。  
  
102行获取参数名，然后121行遍历参数名，124行对 "b_" 开头的参数名进行进一步判断。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicjUqH90odpTrGwWPaS71IVVticW6rxayDYLo8AfbYcyOCPDIicswdCxtA/640?wx_fmt=png&from=appmsg "")  
  
如果是 "b_" 开头的参数名，在131行使用var8（当前url路径）+ "#" + 参数名 进行字符串拼接。  
  
最后在136行执行跳转到 MRMapping.xml 配置文件的路由当中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicAE7IhrLibFz6ZkoFicfpiaXAULaZDSJ0mMtyzFicibshLnDyqibYB6J5ZF3w/640?wx_fmt=png&from=appmsg "")  
  
**总结：这里的拦截器先去ActionBase类判断是否为登录状态，然后跳转到FrameAction类的myexecuteIt方法对所有的参数名和参数值进行过滤关键字（其中包括单双引号），然后使用【url路径+"#"+参数名】拼接成字符串跳转到MRMapping.xml配置文件路径当中。**  
###### 3.1.2.4、MRMapping.xml  
  
打开MRMapping.xml文件，找到刚才拼接的路由：/train/plan/searchCreatPlanList#b_selectPlan。  
  
可以看到function-id="2020020116"。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLic6JeyKAkcrNzichZiah169dxyC0WL23Wcfgm7DEqy8duFiaOtHNVJYIkjQ/640?wx_fmt=png&from=appmsg "")  
###### 3.1.2.5、WFMapping.xml  
  
在WFMapping.xml文件，搜索2020020116，找到class类路径。  
  
<wfi-class mainClass="com.hjsj.hrms.transaction.train.plan.SetSelectedRecordTrans"/>。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLiceWZRhWHErQ3kIFQ5Mq4SVTRqHiatrxaaxXywoLsdp7RKfosbvDbewSQ/640?wx_fmt=png&from=appmsg "")  
###### 3.1.2.6、SetSelectedRecordTrans类  
  
打开该类，14行通过requestPamaHM key获取所有参数名和参数值。  
  
15行获取selectID参数值，传入到PubFunc.keyWord_reback中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicZYMtQSEs9LkPNr5ftL3tDYLE9iciclckjBwM6gKJNVia3bN2ZPPg1MzCQ/640?wx_fmt=png&from=appmsg "")  
  
跟入PubFunc.keyWord_reback，发现居然把本来过滤的单双引号给替换回来了！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicuU9ChhtILXic1K6lSdYFecStGGBhHlOF0ZZxa8ChxwRWcHXxflpIr6A/640?wx_fmt=png&from=appmsg "")  
  
以*符号为分割，直接带入sql语句执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLictFqPNcFibBwC5DdicBCqbXcVcpUbsicrMnIxN0oH1L7wP7EMYaViawiaCAw/640?wx_fmt=png&from=appmsg "")  
  
SQL注入分析到此结束。  
### 四、总结  
  
**这次从黑盒挖 SRC 到 0day 分析的旅程到这里就画上了句号。从整体过程来看，其实并没有使用什么高深的技术，更多是基于常规的 top 漏洞进行分析和挖掘。然而，这样的基础方法依然能带来一些突破，但在当前愈发内卷的环境下，仅仅依靠常规漏洞和传统思维，显然难以脱颖而出，也容易被行业淘汰。**  
  
**因此，作者认为，与其固守常见的挖洞思维，不如更多地尝试拓展攻击面的横向思路。比如，一个看似不起眼的弱口令或信息泄露，往往能引发一连串的安全问题，从而实现链式攻击，这才是未来挖掘的重要方向。**  
  
**作者始终坚定：黑盒的最终目的，是为了更好地服务于白盒安全审计。 黑盒可以帮助我们发现问题，而白盒则是深挖问题根源、从代码层面构筑安全防线的必经之路。**  
  
**最后，作为对这段历程的总结，想与大家分享一个自己的看法：基础虽重要，但在基础之上，只有不断思考和探索新的攻击路径，才能走得更远，看到更多可能性。**  
  
**附上两年前专属的SRC赏金作为这次分享的收尾，也希望这段经历能对大家有所启发。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j6taeOcKcp0VcDNzfooKO0uyagnbbsLicznaicMqw3ibViawTSy7Rz4h7UwQw3MJlDtGes6xc4QvRLI0y6dG92Hibibw/640?wx_fmt=png&from=appmsg "")  
  
  
**往期推荐**  
![](https://mmbiz.qpic.cn/mmbiz_gif/bQv07rEoSgnASDXC53WkoCVAbC73AzGr2gJ1hkgmLJf47DcQBvKhS65n8gFR9Rfr2aeIbyMIbxguySA37OaCNA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
[渗透实战 | 组合拳从0-1 Getshell过程](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488085&idx=1&sn=a4a5660879f0df6f6a27786650a755be&scene=21#wechat_redirect)  
  
  
  
[新功能 | 后台对话的一点新变化 BTTSEC-AIBOT](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488075&idx=1&sn=5a24e03b2ccf281cfbb4d8d4fa509782&scene=21#wechat_redirect)  
  
  
  
[工具分享 | 谁都会用的代理池工具-傻瓜式一键代理池](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488023&idx=1&sn=4b68e239c8bfc60c53c6ec96725f51b3&scene=21#wechat_redirect)  
  
  
  
[渗](http://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247487702&idx=1&sn=364c8e2a8ca7366f9773b1a66bc106cf&chksm=cf1ab284f86d3b9273d7734e6f6eeba4da41acd987c60347dfb14b9c61cb55359d442b66c9d8&scene=21#wechat_redirect)  
[工具分享 | nuclei管理工具＋9w poc不想要嘛？](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488006&idx=1&sn=69194b9ea7c038bace29df89d53fa101&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5XMBWuTy1YdnTAAczP5ENGmlT9xMEAsJuTqV6jib7IyxImNprOeHxrbPLFkKfEPfh2U829KgfaTYB6NLOmx9Ykg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
  
**关注福利：**  
  
回复“  
google工具  
" 获取 google语法生成工具  
  
回复“  
小程序渗透工具  
" 获取 小程序渗透工具  
  
回复“  
暴力破解字典  
" 获取 各种常用密码字典打包  
  
回复“  
typora激活  
" 获取 最新typora激活程序  
  
回复“  
蓝队工具箱  
”即可获取一款专业级应急响应的集成多种工具的工具集  
  
  
**知识星球**  
  
星球里有什么？  
  
CNVD、EDU及SRC赏金，攻防演练资源分享(免杀，溯源，钓鱼等)，各种新鲜好用工具，最新poc定期更新，  
以及一些好东西  
（  
还在学怎么挖通用漏洞吗快来加入  
），16个专栏会持续更新~  
**提前续费有优惠，好用不贵很实惠**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWrow7Lich50u81LLP4zJibgPAraQqDXp7unGFQ4kARpmX2yicpt7hworr5QptZTtCGKsXzicAr24Fy9A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**交流群**  
  
加我联系方式拉交流群~  
  
****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**安全考证**  
  
需要考以下各类安全证书的可以联系我，  
绝对低价绝对优惠、组团更便宜，报名成功先送星球一年，  
CISP  
、PTE、PTS、DSG、IRE、IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理......  
巨优惠  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicVKjibDEuQ9Kib0ia6TibrVmoFRWyXqReDwUhDas8kOqD29OfTA4XzqZjgw1pn8OYibtFfQxvPJq4kNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
