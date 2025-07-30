#  GoT指纹识别、漏洞POC管理扫描工具   
AgentVirus  夜组安全   2024-07-06 10:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2XBasicGV7gEJRXXIbEd6BMCk11twiaxeQcQK1OUEkVw0GOz4lICiafEYLgicyupsianWVoWjL9FIJP5Og/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**工具介绍**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pzeNbYicUYGmM0jvnB7kCbag51wEcMBGyaXC2Ricla7mjLt4tb8g0rsrQ/640?wx_fmt=jpeg&from=appmsg "")  
  
基于sqlite数据对网站指纹和POC进行管理使用，此工具的开发目的就是存储各个框架的识别指纹，和降低批量漏扫poc脚本编写和管理难度。  
  
  
POC数据库支持类似于nuclei poc脚本部分功能（base64解密，正则表达式匹配，提取json字段），以后根据需要会更新更多功能。 ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pic2JkyusbnibFJDSzmyGWFA9rZG3DlRjTa9mMW0ahQGoo5eS4Q1xf2Ww/640?wx_fmt=jpeg&from=appmsg "")  
  
  
指纹数据库基于 网站title，body，图标hash和header对网站框架进行识别 ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pJF8jicwibxD5GyyfIXOB3DFBpPNKUgrsBtApCAeyzyncKXAibGVjMToXQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**02**  
  
**基础功能**  
  
**资产信息识别(Sniff)**  
```
GoT.exe sniff -u http://127.0.0.1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pYemxJ5nwMIyj0HKdLpLcDARxxztqc3SYzFszKLot3ic99S40EhuSsAw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
**sniff模块其他功能**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pj5E9WdGZCJUlYXxNzU8y0j9oSF4ibHShre7PBaN7g1icj7hvYIibYL41w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**开启代理并检测代理位置**  
```
GoT.exe sniff -u http://127.0.0.1 -proxy socks5://127.0.0.1:7890 -pr
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pcHEX3m1P0OMicr9qnmpmVic9v8fjX6JuGMB1gjDlIUmyYOC0OG09TsDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**资产识别＋漏洞扫描**  
```
GoT.exe sniff -u http://127.0.0.1.com:8888 -at
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pkfoPOF3YArjSGv8wVicCXCWSqYNWazNIrQ0w84f81ibowkepm7cB9jYg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**POC+漏扫模块(Attempt)**  
```
-u 单个url
-f txt文件
-condition 通过数据库中的字段匹配漏洞进行漏洞扫描
```  
  
  
使用sqlite数据库工具（DB Browser for SQLite）打开sqlite打开数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pEQx8iaRuD3dT4fUaHhRoQ0jZ00P75Mg8sUhedkCgVRC0nnqicNibNo2jw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
可以看到poc配置信息  
  
  
编写poc的高级函数目前只支持3种：正则表达式，json提取，base64加密。以后会更新支持更多版本的高级函数。  
  
  
**attempt模块功能**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pBLmrmmubfvjPssINH0qU0Ph7HPJgfmoZ0icH1EBq5ibukFs19hEksia0w/640?wx_fmt=jpeg&from=appmsg "")  
  
```
-condition vuln="xxxx漏洞" -condition CMS="xxxOA"
GoT.exe attempt -u http://127.0.0.1:8090 -condition vuln="用友U9-0702-敏感信息泄露-TransWebService"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9p4DF74T2o6WJkttTWcxWGlh0jkmRx6PNpxy0VOBFaRw5lX4XWia0M7Ng/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**与FOFA联动(fofa)**  
  
在command.txt中编写fofa命令，在setting.json中填入key和邮箱  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2UJU4GQnHErU8R85mg9NR9pln6J4e8zV8QJPgzibibjq0g1PpHxatibOkW9puED9jBSaE2o2nJe3cQ1A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**03**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【240706****】获取**  
**下载链接**  
  
  
**04**  
  
**往期精彩**  
  
[ 网络安全监控数据大屏&资产测绘平台+漏洞扫描的前端UI ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247491326&idx=1&sn=5997ab821b78ff5bbefa45d13514ac42&chksm=c3685a06f41fd310f9d0f48df1ccb708e6830d61ea6fa1d94db84328b3583debabb8a6bab4f5&scene=21#wechat_redirect)  

						  
  
  
[ POC管理工具&漏洞扫描&指纹识别综合工具 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247491323&idx=1&sn=db35780e1e52184c2d422455420a0369&chksm=c3685a03f41fd315efab4a16b97e6730426397fac7323f92dd220c77193eeb577a2645d69d89&scene=21#wechat_redirect)  

						  
  
  
[ Python内存马管理工具 Python MemShellResources ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247491322&idx=1&sn=5138a40172a5cd3fcd5030b3106f57ec&chksm=c3685a02f41fd31429b7bb439713c7e848300897fe15ce42cff6d491314bed868a98f7fddf8a&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  
