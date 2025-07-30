> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNzY5MTg1Ng==&mid=2247489822&idx=1&sn=ac39a8e743ae577a5588eb193172e641

#  契约锁电子签章系统RCE简单分析  
Ha1ey  富贵安全   2025-06-30 00:00  
  
**本文章仅供学习交流使用，文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！**  
  
## 前言  
  
  
写一下近期契约锁修复的一个漏洞  
  
## 分析  
  
  
契约锁分为三块服务：电子签约签署平台、电子签约管理控制台、电子签约开放平台，下面分析的漏洞是来自于电子签约管理控制台。  
  
  

```
com.qiyuesuo.config.ConsoleConfiguration
```

  
 这个类有定义前台不需要鉴权的接口，其中就包含了此次漏洞的接口 
```
/setup/dbtest
```

  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8pvpy3Fx1ufa3BzZWnms4nutnqYbgFleYXmJOQictzorV20v9sicQ0ELA/640?wx_fmt=png&from=appmsg "")  
  
  
问题入口点
```
com.qiyuesuo.setup.SetupController#dbtest
```

  
  
  
几个参数**db**  
 、 **host**  
 、**port**  
、**name**  
、**username**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ89jIju3RLlGiayq4zrYhficqNPX5YlMDxSph2NIfemuViccSKMfOZqXskg/640?wx_fmt=png&from=appmsg "")  
  
  

```
com.qiyuesuo.setup.SetupService#check
```

  
 方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8gfdMJibPiciahHdnwUSoib6LoZ7Z1aswz3icq0bJ799FQr3qKiaBLF07vB3g/640?wx_fmt=png&from=appmsg "")  
  
  

```
com.qiyuesuo.setup.SetupService#validateDatabase
```

  
 方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8icTDhGsrBVK1UfeUpTOR0G5PSI8lhlFGQc7jhGib0jZG0rVqj2v9H6qg/640?wx_fmt=png&from=appmsg "")  
  
  

```
com.qiyuesuo.setup.SetupService#dbtest
```

  
 方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8lYLy9lnucibxg35APMib8KlLp8wRqC6hkmCNVduoLMsDcFxYGxfHZiaZA/640?wx_fmt=png&from=appmsg "")  
  
  
后面就是常见的JDBC调用了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8D9w4CnjEgfo2AEWjHKhibKBwkJeU2j2UApEwyHRZs7iayFWvJ25Wh2Bg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8pUibtiblUibkEovcGuftvmTTzicFfGhzaPZVLDvkbXKg5AmWU2uUgosTrQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8P7kIhFTwHbIdmUsCAJfdfNQArPHNgltKsqicBIXEQErkz5wJnPkKjWA/640?wx_fmt=png&from=appmsg "")  
  
  
内置了几个常见的数据库驱动，可以利用RCE  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5kjLxMuu72AlfJibfHqPueQ8LPC4ZP3icVtFgkuqdm93m4w3QSorKFzpgJE57bKKic1gnA7ZpvjWUicHg/640?wx_fmt=png&from=appmsg "")  
  
  
最后放一个poc  
  

```
/api/setup/dbtest?db=POSTGRESQL&host=localhost&port=5511&username=root&name=jdbcurl
```

  
  
原文链接:  
https://xz.aliyun.com/news/18245  
  
