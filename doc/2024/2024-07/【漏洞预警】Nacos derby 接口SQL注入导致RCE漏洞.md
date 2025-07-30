#  【漏洞预警】Nacos derby 接口SQL注入导致RCE漏洞   
cexlife  飓风网络安全   2024-07-22 22:37  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01TZWypqXHWlXwwRuzCgStJYUaShJrEzVBmK8TlBqOOicM1LJYuia1vu6KoQcv1yibM3KTRQM1DqDbZA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**Nacos是一个用于动态服务发现和配置以及服务管理的平台,Derby是一个轻量级的嵌入式数据库,接口/nacos/v1/cs/ops/derby和/nacos/v1/cs/ops/data/removal在使用Derby 数据库作为内置数据源时,用于运维人员进行数据运维和问题排查,在使用standalone模式启动Nacos时,为了避免因搭建外置数据库而占用额外的资源,会使用Derby数据库作为数据源,受影响版本的Nacos默认未开启身份认证,/data/removal接口存在条件竞争漏洞,攻击者可借此接口执行恶意SQL,加载恶意jar并注册函数,随后可以在未授权条件下利用derby sql 注入漏洞（CVE-2021-29442）调用恶意函数来执行恶意代码,此前官方开发者认为属于功能特性,未做处理,后在2.4.0版本中通过增加derbyOpsEnabled选项默认关闭derby 接口来避免被滥用。**影响范围:**nacos(-∞, 2.4.0)com.alibaba.nacos:nacos-config(-∞, 2.4.0)**修复方案:**将组件nacos升级至2.4.0及以上版本将组件com.alibaba.nacos:nacos-config升级至2.4.0及以上版本  
  
**参考链接:**https://www.nacos.io/blog/announcement-derby-ops-api/?source=news_announcement/  
  
