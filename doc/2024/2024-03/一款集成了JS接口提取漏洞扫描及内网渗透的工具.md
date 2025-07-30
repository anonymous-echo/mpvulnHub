#  一款集成了JS接口提取漏洞扫描及内网渗透的工具   
0x7eTeam  系统安全运维   2024-03-09 08:56  
  
**0x01 工具介绍**  
  
该工具就是作者练习javafx的产物，并没有高深莫测的功能，给自己的礼物。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6j93T3RZ0w4LSz46HlZNjEJzpvGUmLnl3LB2z8QIJ9zdRsw7TprXiadRI9veNAaFPhEUps3gEBU8g/640?wx_fmt=png&from=appmsg&wxfrom=13 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6j93T3RZ0w4LSz46HlZNjElWR1Y4I3Xaplibo8p1xxMoDIySnOwtI4ic97kJbMoufqWQkgXOn47N0w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
0x02 功能简介基本内容  
  
设置       代理-----推荐socksAPI配置基本工具      常用命令（爆破、文件上传、RDP相关、防火墙相关、Linux应急）      编码转换（Base64、Unicode、url编码、字符串反转、ASCII、rot13、摩斯）      反弹shell      字典生成      杀软识别DNSLOG(命令执行场景、SQL注入场景、XXE场景、其余中间件场景)空间测绘FoFa      鹰图Quake360漏洞检测与利用      调用py脚本，可以导入url,也可以从空间测绘send过来内网渗透      横向移动(impacket-0.11.0的聚合)PTT          密码喷洒数据库MYSQLORACLEJS接口      实现从网址导出js,从js导出接口，接口的存活探测辅助网站      一些常用的渗透辅助站点收集0x03更新介绍0x7eTeamTools V1.1         2024年1月12日1、修复了反弹shell命令生成功能bug2、修复了某些页面鼠标滚轮功能bug3、新增了js接口的一些处理逻辑3.1针对型如../xx.js、./xx.js、//xx.js等js爬取做了修复3.2针对型如../func、./func、/func等接口处理做了修复0x04 使用介绍功能比较简单，只介绍漏洞检测和JS接口漏洞检测第一步：先配置各种API第二步：选择一个空间测绘第三步：选择自己的脚本，检测即可脚本编写要求【可以参考模板】1、要求只从控制台获取一个参数，内容是url2、检测的结果请输出之控制台3、代理需要自己加到py里面内网横向py调用的`impacket-0.11.0`JS接口第一步：输入网址 获取js第二步，挑选一个感觉有接口的js这里的js不能有参数第三步：(可选)，观察结果，如果有特定的目录，可以添加在前面第四步：选择请求方式，然后点击获取接口状态即可结果工具下载  
  
https://github.com/0x7eTeam/0x7eTeamTools/releases  
  
如有侵权，请联系删除  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpxr9XXibHdW6Eib11FYq0FDZFNMUgDMcqTyfs6iaX8OtFdlL6ypEVHCLrw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
好文推荐  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpzdIMlC9plAr8AiaQRUUvBFXZM2scib9zTnRyp0XZQxSUYAWWS0avKrCA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
[红队打点评估工具推荐](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508839&idx=1&sn=abc801070b0e44475887ddbf7273c2e7&chksm=c3087017f47ff901ecb212aadc22c5cbfc6407da79b43a6f48a355cc3fd8c5af79c113db5fd1&scene=21#wechat_redirect)  
  
  
[干货|红队项目日常渗透笔记](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247509256&idx=1&sn=76aad07a0f12d44427ce898a6ab2769e&chksm=c3087678f47fff6e2b750f41514d933390a8f97efef8ed18af7d8fb557500009381cd434ec26&scene=21#wechat_redirect)  
  
  
[实战|后台getshell+提权一把梭](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508609&idx=1&sn=f3fcd8bf0e75d43e3f26f4eec448671f&chksm=c30871f1f47ff8e74551b09f092f8673890607257f2d39c0efa314d1888a867dc718cc20b7b3&scene=21#wechat_redirect)  
  
  
[一款漏洞查找器（挖漏洞的有力工具）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247507539&idx=2&sn=317a2c6cab28a61d50b22c07853c9938&chksm=c3080d23f47f8435b31476b13df045abaf358fae484d8fbe1e4dbd2618f682d18ea44d35dccb&scene=21#wechat_redirect)  
  
  
[神兵利器 | 附下载 · 红队信息搜集扫描打点利器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508747&idx=1&sn=f131b1b522ee23c710a8d169c097ee4f&chksm=c308707bf47ff96dc28c760dcd62d03734ddabb684361bd96d2f258edb0d50e77cdb63a3600a&scene=21#wechat_redirect)  
  
  
[神兵利器 | 分享 直接上手就用的内存马（附下载）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247506855&idx=1&sn=563506565571f1784ad1cb24008bcc06&chksm=c30808d7f47f81c11b8c5f13ce3a0cc14053a77333a251cd6b2d6ba40dc9296074ae3ffd055e&scene=21#wechat_redirect)  
  
  
[推荐一款自动向hackerone发送漏洞报告的扫描器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247501261&idx=1&sn=0ac4d45935842842f32c7936f552ee21&chksm=c30816bdf47f9fab5900c9bfd6cea7b1d99cd32b65baec8006c244f9041b25d080b2f23fd2c1&scene=21#wechat_redirect)  
  
  
  
**关注我，学习网络安全不迷路**  
  
  
  
