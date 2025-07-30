#  NACOS RCE 0day POC分析及复现   
 哈拉少安全小队   2024-07-15 20:12  
  
> 免责声明：请勿将本项目技术或代码应用在恶意软件制作、软件著作权/知识产权盗取或不当牟利等非法用途中。  
> 本项目提及的技术仅可用于私人学习测试等合法场景中，任何不当利用该技术所造成的刑事、民事责任均与本项目作者无关。  
  
## 资产测绘  
  
当前总计13w资产，请自行判断可利用版本：nacos2.3.2-2.4.0![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4uAvZZXtenzOicfSLpmXUWazDjtVAwxlRefl4G1Vfo076469vWPKzSn8A/640?wx_fmt=png&from=appmsg "null")  
  
## POC分析  
  
从github拿到代码后可以看到漏洞利用代码exp.py使用Python写的，并且试图通过urljoin函数构造两个URL：一个用于数据移除，另一个用于Derby数据库。为了防止配置信息冲突，此处进行数据移除：![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4uSJIhRK7emiawBuiaEAvwkTDRxJqgwrKp5rfZLau9apmicq9bl3qWbg4wQ/640?wx_fmt=png&from=appmsg "null")  
移除后进行derby_url配置：urljoin是Python标准库urllib.parse模块中的一个函数，它用于将两个或多个部分（通常是字符串）组合成一个完整的URL。并且对其中传入的参数分析发现代码是用于执行数据库操作的SQL脚本。这些脚本被用在Nacos作为服务注册中心的Derby数据库配置：  
  
•post_sql：首先调用sqlj.install_jar方法安装一个jar包，并调用SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY方法设置数据库属性。然后，它创建一个名为S_EXAMPLE_{id}的函数，该函数接受一个参数并返回一个字符串。  
•option_sql：在更新数据库中ROLES表中的数据，只保留角色为'1'的记录。这里的条件是ROLE='1' AND ROLE=S_EXAMPLE_{id}({cmd})，意味着只有当角色为'1'且角色等于之前创建的函数S_EXAMPLE_{id}执行的结果时，记录才会被保留。  
•get_sql：最终在config_info表中查询数据，并返回两个字段：一个计数字段b和一个名为a的字段，该字段的值由S_EXAMPLE_{id}函数执行得到。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4uKwibCF6pa159EaaeadNWWWxcqz0nLCxzV6fabhPAT8KJMd6sb96DJuA/640?wx_fmt=png&from=appmsg "null")  
接着对service.py分析，在脚本中发现其payload传入的是一个base64编码的字符串，这个编码的字符串被解码为二进制数据，我们需要对这个payload后的内容解码并且拿到最终传入的内容是什么：![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4ugjY7esuf0pbaiaHGNb7MRVq0UBt0kmuZIx3dCRMGIykMAOrSZwJdOCQ/640?wx_fmt=png&from=appmsg "null")  
解码后作为jar包对其进行分析，分析结果如下：jar使用了一个公共静态方法来接受一个字符串参数（cmd），表示要执行的命令。创建一个StringBuffer对象用于存储命令的输出，并且检查操作系统名称来判断系统使用了那种字符集（UTF-8或GBK）。再使用Runtime.getRuntime().exec(cmd);执行的命令，返回一个对象， 最后从进程的输入流中获取输出，并使用InputStreamReader和BufferedReader来逐行读取和解析输出：![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4uh0aVIGsCcmt3oQ4DPh2Bchwt6ZeqlHzWsUaPWl8ib6pv1ZYzwiarQDIg/640?wx_fmt=png&from=appmsg "null")  
并且还发现这个脚本导入了一个config文件，是在本地创建一个http服务来提供我们利用的jar包的下载地址：![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4umRuSE5Yvz1MMdJiaPz9wNFTRcQ2yL7YQoIRic6NoqlsuoHu8WzeaODGQ/640?wx_fmt=png&from=appmsg "null")  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4ugHiaCgwRXvRg8mtPgicDDMyMC9F1kRVfckQQxYAFw0g3Wia5hfvdPmhNg/640?wx_fmt=png&from=appmsg "null")  
因此我们可以知道整体利用为：我们使用exp.py来加载远程的service.py放置的远程jar包，并使用Derby数据库中的执行命令去执行jar包中的命令。  
> 关于Derby数据库导致的问题：Derby数据库可以执行系统命令，我们将jar包下载到数据库中因为数据库特性在更新或查询数据时会调用系统命令，最终把传入的参数当作系统命令来执行。  
  
## 漏洞复现  
  
github下载源码搭建环境：启动环境：  
  
```
startup.cmd -m standalone
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4uwtfpVFEQicvb28AnN2NiclSZGJPRdfzrdrcDsIYkLhfZibaq1pgckhnzw/640?wx_fmt=png&from=appmsg "null")  
复现漏洞执行ipconfig命令：![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LsJkSCCD2LaJLOJC2J0g4uCkflSBlmPfbEzVlFDKb7XdrfrGe8maLXR9ebTGremAEb1Z53mFCoicA/640?wx_fmt=png&from=appmsg "null")  
  
## 总结  
  
下午看到公众号都在转发这个0day就分析了一下poc和打法，这个漏洞需要权限登录到后台才能实现RCE，该漏洞还可以搭配nacos其他的漏洞实现组合漏洞，例如：任意创建用户+该RCE可以实现组合漏洞。最后，建议升级到最新版本或者打上补丁。  
  
[NACOS RCE 0day POC 已公布](http://mp.weixin.qq.com/s?__biz=Mzk0MTY5NzYyOA==&mid=2247485470&idx=1&sn=9fc0c744c366ab9820aca53a9418e355&chksm=c2cf372df5b8be3b3939b1dfcb7b12e15fa11ab5dd85519aab3dfd7a5a98d5910d32c6dcf5ee&scene=21#wechat_redirect)  
  
  
  
https://github.com/ayoundzw/nacos-poc  
  
  
  
