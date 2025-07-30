#  JAVA 插件化漏洞扫描器，Gui基于javafx。POC 目前集成 Weblogic、Tomcat、Shiro、Spring等   
Artillery  夜组安全   2023-11-26 08:00  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehicibhdXDeRwI1L5DC694At2gRAQvUOyPLLNqR8icO1yibl8MAKMN5Vtiawxibch7gQfH1aSia7F6z55Nibu3A/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehicibhdXDeRwI1L5DC694At2gRAQvUOyPLLNqR8icO1yibl8MAKMN5Vtiawxibch7gQfH1aSia7F6z55Nibu3A/640?wx_fmt=gif "")  
  
**安全工具**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehicibhdXDeRwI1L5DC694At2gRAQvUOyPLLNqR8icO1yibl8MAKMN5Vtiawxibch7gQfH1aSia7F6z55Nibu3A/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehicibhdXDeRwI1L5DC694At2gRAQvUOyPLLNqR8icO1yibl8MAKMN5Vtiawxibch7gQfH1aSia7F6z55Nibu3A/640?wx_fmt=gif "")  
  
  
**01**  
  
**工具介绍**  
  
JAVA 插件化漏洞扫描器（Weblogic、Tomcat、Spring...），Gui基于javafx，POC 目前集成 Weblogic(21个)，Tomcat(2)、Shiro、Spring等陆续更新中。  
- 插件化  
  
- 批量扫描  
  
- 支持多个Java中间件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X68MJx914MX7cjLhP1l0qIYNDVP5LY5GxPId0EZVOrvFEBtUS3k2WuUgrsAvqzicfuA2SRbjTjHFg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**02**  
  
**工具使用**  
  
POC插件目录放在同目录下  
目录结构如下，Plugin/中间件类型/libs(poc的依赖)、payloads(poc本体)/。  
```
├── Plugin
│   └── weblogic
│       ├── libs
│       │   ├── commons-codec-1.2.jar
│       │   └── commons-collections-3.1.jar
│       └── payloads
│           ├── CVE_2015_4852.jar
│           ├── CVE_2016_0638.class
│           ├── CVE_2016_3510.class
│           ├── CVE_2017_3248.jar
│           ├── CVE_2018_2628.class
│           ├── CVE_2018_2893.class
│           ├── CVE_2018_3191.class
│           ├── CVE_2019_2890.class
│           ├── CVE_2020_2551.class
│           ├── CVE_2020_2555.class
│           └── CVE_2020_2883.class
└── artillery-1.0-SNAPSHOT-jar-with-dependencies.jar
```  
  
扫描器UI  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X68MJx914MX7cjLhP1l0qIYNDVP5LY5GxPId0EZVOrvFEBtUS3k2WuUgrsAvqzicfuA2SRbjTjHFg/640?wx_fmt=png&from=appmsg "")  
  
右键添加扫描任务，任务目标支持多个。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X68MJx914MX7cjLhP1l0qIDsOp7cXI9INj1cSiaTUS8ln1cLbushf3SsRRiboqKg39cbeNm8XbOUSQ/640?wx_fmt=png&from=appmsg "")  
  
扫描截图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X68MJx914MX7cjLhP1l0qIYNDVP5LY5GxPId0EZVOrvFEBtUS3k2WuUgrsAvqzicfuA2SRbjTjHFg/640?wx_fmt=png&from=appmsg "")  
  
  
**03**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【231126****】获取**  
**下载链接**  
  
  
**04**  
  
**往期精彩**  
  

							[ 双“十一”这个永久的渗透武器库直接低价冲 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247488785&idx=1&sn=d6c7c9cbd0304d6e9eecb01d2806d540&chksm=c36851e9f41fd8ffa26b9498dcd992a92dfb016e4417affe1bdbf9b1d6455bc9cfc260e035bd&scene=21#wechat_redirect)  

						  
  
  

							[ Burpsuite - Route Vulnerable Scanning 递归式被动检测脆弱路径的burp插件 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247489008&idx=1&sn=8055c41771f49d61b0f7a66795fb10da&chksm=c3685108f41fd81ebc4f92684a97cce6606822c18f6ac39f0fde10eefc4a69907937c3dbe115&scene=21#wechat_redirect)  

						  
  
  

							[ 互联网厂商API利用工具 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247488953&idx=1&sn=a32b569c5444e2e92fd9ddaef77e052d&chksm=c3685141f41fd8572bd1169b9bf390f2358b9da782d19167486d19cc6470f26a1ffca11c4a8b&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  
