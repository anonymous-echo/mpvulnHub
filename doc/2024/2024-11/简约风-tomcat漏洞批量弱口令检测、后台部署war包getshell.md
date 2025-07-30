#  简约风-tomcat漏洞批量弱口令检测、后台部署war包getshell   
 LemonSec   2024-11-09 09:13  
  
**1**►  
  
**工具介绍**  
  
  
简约风-tomcat漏洞批量弱口令检测、后台部署war包getshell，该脚本用于检查Apache Tomcat管理页面的弱密码，并尝试通过上传自定义WAR包部署Godzilla Webshell。如果成功，将记录成功登录的信息以及获取到的Webshell地址。作者：**lizhianyuguangming**  
  
  
**2**►  
  
**技术细节**  
  
1. **弱密码检测**  
：根据提供的用户名和密码列表，检查目标URL是否存在弱密码。  
  
1. **WAR文件生成**  
：生成包含Webshell的WAR文件，并上传至目标服务器。  
  
1. **Webshell获取**  
：上传成功后，尝试访问Webshell并记录URL。  
  
1. **多线程支持**  
：动态调整线程池大小，确保资源使用合理。  
  
1. **配置灵活**  
：通过配置文件设置重试次数、重试间隔和线程池大小，适应不同的环境需求。  
  
Starred多后续考虑添加tomcat 文件上传 (CVE-2017-12615)、tomcat 代码执行 (CVE-2020-1938)等漏洞检测。  
  
  
  
**3**►  
  
**工具使用**  
  
1. 准备包含URL、用户名和密码的文本文件，分别命名为urls.txt、user.txt和passwd.txt。  
  
1. 在config.yaml中配置文件路径和其他设置。  
  
1. 运行脚本，将会在success.txt文件中记录成功的登录信息和Webshell的URL。  
  
```
python TomcatWeakPassChecker2.1.py
```  
  
  
运行脚本后，将尝试在 http://example.com/manager/html 使用 user.txt 和 passwd.txt 中的组合进行登录，并记录成功的结果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBALcgGV46AqH0dmrrp1u6LbY21NxekfWwBt326cJ58uatiaMAAoOKE5RAoAqeLibl139icD4CpNnd6Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**4**►  
  
**工具获取**  
  
https://github.com/lizhianyuguangming/TomcatWeakPassChecker  
  
**侵权请私聊公众号删文**  
  
  
 **热文推荐******  
  
- [蓝队应急响应姿势之Linux](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523380&idx=1&sn=27acf248b4bbce96e2e40e193b32f0c9&chksm=f9e3f36fce947a79b416e30442009c3de226d98422bd0fb8cbcc54a66c303ab99b4d3f9bbb05&scene=21#wechat_redirect)  
  
  
- [通过DNSLOG回显验证漏洞](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523485&idx=1&sn=2825827e55c1c9264041744a00688caf&chksm=f9e3f3c6ce947ad0c129566e5952ac23c990cf0428704df1a51526d8db6adbc47f998ee96eb4&scene=21#wechat_redirect)  
  
  
- [记一次服务器被种挖矿溯源](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523441&idx=2&sn=94c6fae1f131c991d82263cb6a8c820b&chksm=f9e3f32ace947a3cdae52cf4cdfc9169ecf2b801f6b0fc2312801d73846d28b36d4ba47cb671&scene=21#wechat_redirect)  
  
  
- [内网渗透初探 | 小白简单学习内网渗透](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523346&idx=1&sn=4bf01626aa7457c9f9255dc088a738b4&chksm=f9e3f349ce947a5f934329a78177b9ce85e625a36039008eead2fe35cbad5e96a991569d0b80&scene=21#wechat_redirect)  
  
  
- [实战|通过恶意 pdf 执行 xss 漏洞](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523274&idx=1&sn=89290e2b7a8e408ff62a657ef71c8594&chksm=f9e3f491ce947d8702eda190e8d4f7ea2e3721549c27a2f768c3256de170f1fd0c99e817e0fb&scene=21#wechat_redirect)  
  
  
- [免杀技术有一套（免杀方法大集结）(Anti-AntiVirus)](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523189&idx=1&sn=44ea2c9a59a07847e1efb1da01583883&chksm=f9e3f42ece947d3890eb74e4d5fc60364710b83bd4669344a74c630ac78f689b1248a2208082&scene=21#wechat_redirect)  
  
  
- [内网渗透之内网信息查看常用命令](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522979&idx=1&sn=894ac98a85ae7e23312b0188b8784278&chksm=f9e3f5f8ce947cee823a62ae4db34270510cc64772ed8314febf177a7660de08c36bedab6267&scene=21#wechat_redirect)  
  
  
- [关于漏洞的基础知识](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523083&idx=2&sn=0b162aba30063a4073bad24269a8dc0e&chksm=f9e3f450ce947d4699dfebf0a60a2dade481d8baf5f782350c2125ad6a320f91a2854d027e85&scene=21#wechat_redirect)  
  
  
- [任意账号密码重置的6种方法](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522927&idx=1&sn=075ccdb91ae67b7ad2a771aa1d6b43f3&chksm=f9e3f534ce947c220664a938bc42926bee3ca8d07c6e3129795d7c8977948f060b08c0f89739&scene=21#wechat_redirect)  
  
  
- [干货 | 横向移动与域控权限维持方法总汇](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522810&idx=2&sn=ed65a8c60c45f9af598178ed20c89896&chksm=f9e3f6a1ce947fb710ff77d8fbd721220b16673953b30eba6b10ad6e86924f6b4b9b2a983e74&scene=21#wechat_redirect)  
  
  
- [手把手教你Linux提权](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522500&idx=2&sn=ec74a21ef0a872f7486ccac6772e0b9a&chksm=f9e3f79fce947e89eac9d9077eee8ce74f3ab35a345b1c2194d11b77d5b522be3b269b326ebf&scene=21#wechat_redirect)  
  
  
  
  
  
**欢迎关注LemonSec**  
  
  
**觉得不错点个“赞”、“在看”**  
  
