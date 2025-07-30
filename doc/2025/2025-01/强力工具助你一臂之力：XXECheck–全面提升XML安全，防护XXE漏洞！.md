#  强力工具助你一臂之力：XXECheck–全面提升XML安全，防护XXE漏洞！   
原创 track  泷羽Sec-track   2025-01-18 11:07  
  
>   
> 声明！本文章所有的工具分享仅仅只是供大家学习交流为主，切勿用于非法用途，如有任何触犯法律的行为，均与本人及团队无关！！！  
  
  
  
后台回复**25118**  
即可获取  
  
**往期推荐：**  
  
**2024Goby红队版工具-附2024年poc合集，支持导入自定义poc库**  
  
**一款功能强大的红蓝对抗工具Potato Tool-具备免杀,提权,漏扫,内存马生成,ai分析,溯源等高效的网络安全综合工具**  
  
**渗透必备工具-Burpsuite最新专业版中文破解安装教程及代理配置，附鼠标光标错位移位解决教程**  
# XXECheck  
  
**XXECheck**  
 是一种用于**检测和防止 XML 外部实体 (XXE) 注入攻击**  
的安全工具或库，一款XXE漏洞检测工具，支持 DoS 检测（DoS 检测默认开启）和 DNSLOG 两种检测方式，能对普通 xml 请求和 xlsx 文件上传进行 XXE 漏洞检测。  
## 什么是XXE漏洞  
  
**XXE**  
（XML External Entity,  XML外部实体）漏洞是一种与XML处理相关的安全漏洞。它允许攻击者利用XML解析器中对外部实体的处理能力，通过注入恶意的外部实体，控制目标系统的行为，从而实现信息泄露、拒绝服务（DoS），甚至远程代码执行等攻击  
## 环境准备及错误解决  
  
看看使用帮助 ，如果**python3**  
没有回显，则使用**python**  
```
python XXECheck.py -h
python3 XXECheck.py -h

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfbYfziaicaGGF05PdOTsLFUXt3hSkelamGLfKvYXmc4yNBIl5cgyqVNxOA/640?wx_fmt=png&from=appmsg "")  
  
image-20250118184751589  
  
**翻译**  
一下  
```
XXE 漏洞检测工具
选项：
  -h, --help         显示帮助信息并退出
  -t [request,xlsx], --type [request,xlsx]
                     指定操作类型: 'request' 用于正常的请求操作，'xlsx' 用于上传 XLSX 文件。
  -d DNS, --dns DNS  DNS 请求链接。
  -f FILE, --file FILE
                     请求数据文件路径，例如 Burp Intruder 请求包。
  --nodos            禁用 DOS 检测功能。

```  
  
看看**XXECheck.py**  
代码里的内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfbKEHxwUO4v76TGLXib2pZC5yiaR0HYW4A9gBKCMzFmK9Fd7WTsrMOt4MQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250118184954608  
  
首先代码正常运行需要上面的**模块**  
，不能有缺失，如果发现有模块缺失的。比如我下面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfbMhnFn4VokbCyQHOiaGmyuiavggpoeRjC4aBIcaGudkP7r2QtTRwZ8eGA/640?wx_fmt=png&from=appmsg "")  
  
image-20250118185147986  
  
则需要**下载该模块**  
```
pip install 缺失的模块

```  
  
全部模块都具备后才可正常使用  
## 使用说明  
  
对普通请求进行检测，指定请求包为 1.txt，-d 添加 dnslog 链接，不加只进行 DoS 检测，如果不想使用 DoS 检测请添加 --nodos  
```
python3 XXECheck.py -t request -f 1.txt -d dnslog

```  
  
如果不指定请求包，则会生成检测 POC，手工检测  
```
python3 XXECheck.py -t request -d dnslog

```  
  
对 xlsx 上传功能进行检测，指定请求包为 1.txt，-d 添加 dnslog 链接，不加只进行 DoS 检测，如果不想使用 DoS 检测请添加 --nodos  
```
python3 XXECheck.py -t xlsx -f 1.txt -d dnslog

```  
  
如果不指定请求包，则会生成带有 POC 的 xlsx 文件，手工检测  
```
python3 XXECheck.py -t xlsx -d dnslog

```  
## 免责声明  
- **本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。**  
  
- **在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行测试。**  
  
- **如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。**  
  
- **除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。**  
  
# end  
## oscp  
  
有对红队工作感兴趣，或者有意报考oscp的师傅，可以考虑一下我们的培训课程，加我微信咨询，好处如下：  
  
**1.报考后课程随时可看，并且如果对考试没有信心，还可以留群跟第二批课程学习，不限次数时间，报考即是一辈子可看**  
  
**2.200+台靶机及官方课程，lab靶机+域的内容团队泷老师和小羽老师会带大家全部过一遍，并且群内随时答疑，团队老师及群友都会积极解答，全天可答疑**  
  
**3.目前可接受分期付款，无利息，最多分四个月，第一次付完即可观看视频**  
  
**4.加入课程可享受工作推荐机会，优秀者可内推至红队，月薪3w+**  
  
**5.报考即送送官方文档中文版，以及kali命令详解中文版，纯人工翻译，版权为团队所有**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfbLJDsctr32fib9Vvrg0eWOsg88W81ZMEDaA2kq12eib4lNWI9xpZQGoRw/640?wx_fmt=png&from=appmsg "")  
  
**资料：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfb3VrACWw1cmMQeghjh0hH3pDL8iaruPLLvFeDLy6nJ5FVKBLskWjozLA/640?wx_fmt=png&from=appmsg "")  
## 知识星球  
  
**还可以加入我们的知识星球，包含cs二开，甲壳虫，网恋避险工具，红盟工具等，还有很多src挖掘资料包**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfbPtUQYKcgar5Z7hibuU3Z9AoXl43fcFWTNwlDjbhs7vZwa8woBquHUmw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfb9tiaE7kVXvES5SqoQlt6nacRTjatoOyUTt3DKpSmVVE3nhjeibXgvn1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfb87o5Dh4KF8JIaNyulfP957NM9R6Apd79BfrXM7cxz1Wy7OHflgng7A/640?wx_fmt=jpeg&from=appmsg "")  
## 学习交流群  
  
在**公众号后台**  
这里选择**学习交流**  
即可，如果图片二维码过期，可以加我微信获取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw3VyHcgYzAibOWrckjcRxXfbEp06iafD7GONOsS4PJw8Lh1UQLDSTwgQO2Jna0cMu7EwK3FLlgxSYicA/640?wx_fmt=png&from=appmsg "")  
  
  
  
