#  契约锁电子签章系统RCE简单分析  
原创 Ha1ey  安全白白   2025-06-11 10:53  
  
   
  
# 契约锁电子签章系统RCE简单分析  
  
**Ha1ey@深蓝攻防实验室**  
  
**本文章仅供学习交流使用，文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！**  
## 前言  
  
写一下近期契约锁修复的一个漏洞  
## 分析  
  
契约锁分为三块服务：电子签约签署平台、电子签约管理控制台、电子签约开放平台，下面分析的漏洞是来自于电子签约管理控制台。  
  
com.qiyuesuo.config.ConsoleConfiguration  
 这个类有定义前台不需要鉴权的接口，其中就包含了此次漏洞的接口 /setup/dbtest  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLobnaVGHKIUVkniaT8P2HtoLvekYt7TeIxkUMhkjL13RNSUzJctguWM4w/640?wx_fmt=png&from=appmsg "")  
  
  
问题入口点com.qiyuesuo.setup.SetupController#dbtest  
  
几个参数**db**  
 、 **host**  
 、**port**  
、**name**  
、**username**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLo3c70lC1TxtdNa6GTibhkVXSFykic2lOqjsGN2axxCsdrhnHvsGRCkD4w/640?wx_fmt=png&from=appmsg "")  
  
  
com.qiyuesuo.setup.SetupService#check  
 方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLojLLHB1RU2ibASM61lKOprJeQ5WfhmZ7kJiacYTcTK9xuvYnHiaSxAn9Aw/640?wx_fmt=png&from=appmsg "")  
  
  
com.qiyuesuo.setup.SetupService#validateDatabase  
 方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLoCPFuOqOE2PznZmibAUukpGpoEFXYM8KkZqcwDtlYV5kVQe8WX8hTVWg/640?wx_fmt=png&from=appmsg "")  
  
  
com.qiyuesuo.setup.SetupService#dbtest  
 方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLoeE7zHH2iaeQG7EJvC4RKLsQxGiaZQFjrcjaytB5vtmUJvldJv8SuzicJQ/640?wx_fmt=png&from=appmsg "")  
  
  
后面就是常见的JDBC调用了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLo1V5ibPoTQ0UHr6kiaMv5dZRzHssxdvbfVlwicjNKEg3ibmlPvSXo8rz0qQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLodkticppDFfCT9BXjfjsa8PT8dia5S3MasWSuE7nVk1AZDtWx2icJIcrvg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLodkticppDFfCT9BXjfjsa8PT8dia5S3MasWSuE7nVk1AZDtWx2icJIcrvg/640?wx_fmt=png&from=appmsg "")  
  
  
内置了几个常见的数据库驱动，可以直接RCE  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9opkGjmlwBIoohJcTB5ylLobRlFtp7gvWTPfKgPwSha7QS9wxxxNwJicFiady2tvoEJa5UBN8wFTjqA/640?wx_fmt=png&from=appmsg "")  
  
  
最后放一个poc  
```
/api/setup/dbtest?db=POSTGRESQL&host=localhost&port=5511&username=root&name=jdbcurl
```  
  
  
   
  
本文首发于先知社区：  
https://xz.aliyun.com/news  
  
