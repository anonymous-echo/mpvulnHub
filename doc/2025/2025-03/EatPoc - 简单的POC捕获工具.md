#  EatPoc - 简单的POC捕获工具   
 LemonSec   2025-03-02 16:00  
  
又到每年大小考的时候了，很多非开源扫描器会集中再这段时间疯狂推送新的POC。大秀肌肉。  
  
有时候不想启用mitmproxy去精细化抓取流量，只想批量保存POC。所以做了这么一个脚本去完成需求。  
  
该工具保存下载的流量(request)，可以再用大模型修改格式，比如改成Nuclei支持的格式。  
  
  
项目地址  
```
https://github.com/yangliukk/EatPoc
```  
  
  
简介  
  
EatPoc是一个简单的模拟mitmproxy功能的HTTP请求捕获、记录和转发工具。  
  
该工具全程面向大模型开发,使用DeepSeek生成主要功能代码,通过Cursor进行优化调整。由于开发方式的特殊性,可能存在一些bug或需要改进的地方。欢迎提出建议和反馈。  
  
使用场景  
  
非开源扫描器POC更新，想进行学习或分析。但查看流量、日志等信息需要跨部门合作。该工具将接收、转发流量并保存到本地。  
  
以xpoc举例  
  
假设运行EatPoc.py的主机IP为：192.168.1.3，默认监听 8000端口  
```
# 获取所有POC
python EatPoc.py 
 
./xpoc -t http://192.168.1.3:8000
 
# 扫描器需要取信息，才能打第二步POC
# 将接收到的流量转发到存在漏洞的系统上
python EatPoc.py -p 8000 -t http://target-server.com
 
./xpoc -t http://192.168.1.3:8000
 
# 转发的目标漏洞系统是HTTPS
python3 EatPoc.py --generate-cert   //生成证书
python3 EatPoc.py -p 8000 --https -t https://target-server.com
 
./xpoc -t https://192.168.1.3:8000  //扫描器也需填https开头
```  
  
运行时的截图  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/p5qELRDe5icnNo8CCAuZSRI9FbmK3gvWXNUGllyGKPXfW8SG3uLFgUnja33cabry4NicGZP1YjYxBoYnbkhibokibg/640?wx_fmt=png&from=appmsg "")  
  
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
  
