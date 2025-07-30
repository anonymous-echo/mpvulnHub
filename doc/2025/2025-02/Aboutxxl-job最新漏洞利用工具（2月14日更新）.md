#  Aboutxxl-job最新漏洞利用工具（2月14日更新）   
charonlight  Web安全工具库   2025-02-17 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtZlYibB9L1ibCdWv25PZo1j4J9UqvCdeWxniby2M2QAUMHrC7VAFzSt4UIFWNzUyqx1x6AibsibnpTWmA/640?wx_fmt=png&from=appmsg "")  
  
**0x02 安装与使用**  
  
一、工具检查能力  
```
工具目前支持如下漏洞的检测，我们也会持续添加poc和各种漏洞利用方式。

XXL-JOB-Admin 默认登陆密码
XXL-JOB-Admin 后台RCE  ( 工具支持利用模块 :  内存马注入  )
XXL-JOB-Admin 前台api未授权 hessian2反序列化  ( 工具支持利用模块 :  命令执行 内存马注入  )
XXL-JOB-Executor Restful API 未授权访问命令执行  ( 工具支持利用模块 :  命令执行  )
XXL-JOB-Executor 默认accessToken权限绕过  ( 工具支持利用模块 :  命令执行  )
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtZlYibB9L1ibCdWv25PZo1j4ROdshLYOQnia0v9rwsWne090jfDMenaXr3dnDllfYrQL8hDJAgicngCw/640?wx_fmt=png&from=appmsg "")  
  
二、  
工具也支持资产测绘和批量扫描![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtZlYibB9L1ibCdWv25PZo1j4ctkPRxAGib4VS4icuNic8ohbB0NY1nyvlzbvqF8L2iccZZial2fAq7Xibcicw/640?wx_fmt=png&from=appmsg "")  
  
  
三、漏洞利用  
  
Hessian2反序列化命令执行![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtZlYibB9L1ibCdWv25PZo1j4ib7x4MoCQ0srTBAHjBT8LviahWBuNCtG4KagKLnVgCs1OqwcY5Uq4IAw/640?wx_fmt=png&from=appmsg "")  
  
  
Hessian2反序列化注入内存马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtZlYibB9L1ibCdWv25PZo1j4icb5bicCaDm7H0JKKXxFicgyqtzpeExvRkWibnu6kDUicqXMrzbmq53ZkTw/640?wx_fmt=png&from=appmsg "")  
  
后台一键注入vagent内存马，需要再设置里面配置好Cookie （目前仅支持部分版本，且需管理端和执行端在同一台服务器）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtZlYibB9L1ibCdWv25PZo1j4pQnrB00B91HKYJLpkt57dR3M2mcxpV4cuoF6oW4ofJxmEgfpn1kaPQ/640?wx_fmt=png&from=appmsg "")  
  
目标中需要xxl-job的二级目录，注入添加的执行器和日志会进行自动删除  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtZlYibB9L1ibCdWv25PZo1j4j88TtGsW8XSDrKBrQfIxCPAotVCSptl32JZqYib7EDqgWecIXYl7pVQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**·****今 日 推 荐**  
**·**  
  
> 本书全面系统地介绍了Java语言编程，共包含15章内容，涵盖了Java的基础语法、面向对象编程、常用类库、GUI编程、数据库访问、网络编程、多线程等核心知识点和编程技能。  
书中大部分知识点后都设计了针对性的训练营，通过大量示例和综合练习案例，帮助读者深入理解知识并灵活运用。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuwjcgwBkythEwtMIIa7Xl5r8JvHIYrVpWVxicwTr0rWNYkhCqWichkUhkQCeulxBJaqOWCatpLDoFg/640?wx_fmt=png&from=appmsg "")  
  
  
  
