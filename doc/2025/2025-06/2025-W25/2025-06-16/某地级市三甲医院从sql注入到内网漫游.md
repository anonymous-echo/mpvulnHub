> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNzQyMDkxMQ==&mid=2247488241&idx=1&sn=08984a5ec6088a6665018d68ab8b6eb6

#  某地级市三甲医院从sql注入到内网漫游  
 赤弋安全团队   2025-06-16 07:56  
  
## 外网打点    
### 开局一个超管！    
  
  
拿到资产后，开始打点，做信息收集，发现外网资产不多，都是xxx系统，用弱口令拿下超管账号  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvMhvxYK44S95NJCABF8YibJZKYgKechvU3TyDvMMuz7zNnUApibIicIjCw/640?wx_fmt=png "")  
  
  
  
  
找上传点，有导入execl功能，但是这种一般都是导入后提取数据出来，作用不大，然后在公告发布出找到上传点  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvgYZFLicd5QVMsYibiazGwleibQNvJ7hX9XA76buRxJNPeTemZCD1fmQiaaA/640?wx_fmt=png "")  
  
  
  
  
上传jsp webshell，前端传png抓包改jsp，返回上传路径  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nv8QOztoZsCiaoUQiapIxjPrdR5CRNfkshoyI4lXZThn6QwwuIz3YQ7X2g/640?wx_fmt=png "")  
  
  
  
  
本来以为直接拿下了，访问直接跳下载，说明目录没有执行权  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvB1u351Bx9yAqhDqnz9VBpVd72Xw7OeqbpUj4FNRGm8CXBliaLvDl6xw/640?wx_fmt=png "")  
  
  
      
  
  
尝试跳目录上传，目录也不可控同时重命名  
  
  
继续翻翻找找在一个查询接口出找到一个get注入，排序处很容易出sql注入  
  
  
http://1.1.1.1/xxx/xxxx/xxx?credentialId=301353544&credentialSource=4&venCode=1998&sort=ASC,if(length(CURRENT_USER)=18,1,exp(999))              
  
  
mysql数据库，除了拿到一些数据，没什么用，只能换个资产继续打  
### 白嫖管理员    
  
  
换个ip，也是xxx在线学习平台，在8000端口，asp的站，伪静态除了一些宣传页面，还有几个链接到其他系统的地址，但都是内网地址  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvnicDqmGlsXOqx3icvLapxB7sI9HUF7eM371LBM6O1DGmOBCVJ4QxHCQw/640?wx_fmt=png "")  
  
  
  
  
首页是没什么功能点的，扫了下目录，找到后台，/user/login.asp，试了几个弱口令，发现没有，而且登陆口账号写明为手机号，测试了下admin，报错提示密码错误，账号枚举是存在admin账号的  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nv6Uib7ia6bCBnNXDS92SSY7ydrYfXxGibXue5ictHawxtpHQbF4VrR3GHMw/640?wx_fmt=png "")  
  
  
  
  
爆破密码无果，一时陷入僵局，只能开个大字典继续扫目录，这次发现一个最开始没有扫出来的目录  
      
  
  
http://xxxx/User/ManagerCard.aspx              
  
  
访问直接跳转  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvQFFaqhLg8wGFFWZD7putoAoboNhGLLGiaJJl5zmIORxt4pBe2kibVicMQ/640?wx_fmt=png "")  
  
  
  
  
直接到了管理员添加界面，未授权直接添加管理员，添加管理员的时候，头像处可以上传，上传图片抓包改asp，但是问题又出现了，直接500  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvVgIszpH1ZGWshutCFPpNWngsbtHBw96KmHoTXgUiaEaOyaUnICnzrFw/640?wx_fmt=png "")  
  
  
  
  
一开始以为是有杀软，尝试cer，aspx等后缀都500，尝试正常的png后缀也是500，那么就不是杀软了，只能先添加一个管理员账号  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvIMbVlkOicjuLgQxRf1D5NkEoyaB35IYribvjldqd4VEKx81VsFgGezOA/640?wx_fmt=png "")  
  
  
      
  
  
继续找上传功能，但全部都是500，意识到功能接口可能直接关闭了，同时所有查询接口，页面链接，全部为加密为密文，且过滤单双引号，没办法注入，这个目标也陷入僵局，只拿下一个后台权限，拿不下就继续换资产打！  
### 柳暗花明之还差一点    
  
  
在收集到的资产里继续找目标，发现一个8083端口的网站打开跟上面这个xxx在线学习平台一样，属于同一个cms，直奔上面的未授权，发现这个cms做了鉴权，同时跟上面8000端口的站一样，cookie，页面链接和参数，全部都是密文，又没有其他功能，常规攻击根本没有办法，这个时候看到页脚，发现版本为，3.x，第一个为1.x，那么他们会不会使用同一个数据库？  
  
  
尝试使用最开始未授权添加的管理员登陆，居然成功登陆！两个站，两个版本，但是是同一个数据库！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvc3t827p9lNY2hUhxJcvg6HHHkMufJbhI81Ym3Vm6e7q4xqCOFlOwNg/640?wx_fmt=png "")  
  
  
  
  
这次上传功能正常，开始上传webshell，但是发现问题并不简单，后台对上传文件做了限制，只允许图片格式，html，txt，个人判断为白名单。使用大小写双写等等办法发现根本无法突破限制，使用：：特殊符号截断会把整个后缀截断，可以传上去为，http：//1.1.1.1/upload/adasdadszxc 无后缀形式  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvCYuz9cbyXljpSTSyMFSVfMYSeDicBAzCFBol5Gicb17buNSkYEialdfHA/640?wx_fmt=png "")  
  
  
  
  
但是也不存在iis解析漏洞。翻翻其他功能，上传宣传页面可以造成存储型xss，也拿不到权限，至此出师未捷身先死，这个点又断掉了  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvDpa4ibrn7kY1enZuRBv3QwLkfFFFQLRuspNZpLjibKnw9mibBBFUARw2w/640?wx_fmt=png "")  
  
  
### 峰回路转拿下权限    
  
  
上面几个都拿不下权限，只能再次换资产扫完端口发现存在一个81端口，访问404，看一下指纹iis，这种情况比较常见，服务存在，但是访问404，一般可能就放弃了  
  
  
但是渗透比的就是细！开始扫目录，换了多个字典以后发现存在一个1.1.1.1/dms路径，访问跳转，经典登陆口，xxx管理系统  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvqShcd3fFu912CIly2akicP3VOvWaNbpDjPZ0T7fQH4xbkcNBSuuGkrA/640?wx_fmt=png "")  
  
  
  
  
手工尝试几个弱口令，无果，爆破admin也无结果  
  
  
这个时候转念一想，这种管理系统不一定只有管理员，会不会存在用户？毕竟是医院，有医生各种职工，随即用弱口令123456去撞账号，一下撞出好几个  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvzCsBYcMdx3xqiav8n6elyMN2KInHKjiaY3T3ibxiaca4Z5xRnhWy7Of6aw/640?wx_fmt=png "")  
  
  
  
  
美滋滋登陆，护士权限不高，也没有上传点，只有导入，前面说过导入是没有用的  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvCPvEEwOzHmENKC5gl1ia8icCIgHz483HTyosz84hGibkqWKIozF8D43pA/640?wx_fmt=png "")  
  
  
  
  
继续翻功能，iis+asp搭建多半是sqlserver，往各种查询数据包里丢单双引号，存在注入！  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvQsbFKhp4BywJX4e3wfkHK0M6zGNoJRX4ibDic5nvwhAGkfZGjvR5KcKg/640?wx_fmt=png "")  
  
  
2008+sqlserver！  
      
  
  
报错拿到真实路径，其实就是自身功能，点一下直接报错  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvFQCqyXGhwkr8ibLGZe6ycjRb2ntIagftX0mmhkOeReZ40tEdI6IDrqg/640?wx_fmt=png "")  
  
  
  
  
丢sqlmap发现跑不出，发现有语句执行有长度限制，换个点，手工开启xpcmd_shell，可能是这个点藏的比较深，没有waf拦截  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nv7Nb5URHtFJ0XEcaZ8mL4629v0YAKKYqwggcwWyTIPdBhQuPMjB2xmw/640?wx_fmt=png "")  
  
  
  
  
但是有杀软，调用xpcmd直接写马被拦截后（360/火绒好像不拦xpcmdshell低危命令所以前面可以执行whoami），触发告警，权限直接掉了。一度认为权限直接无了，不过因为是在休息日打的，无人应急响应。等了很久很久很久，才恢复（估计是长时间不处理杀软初始化了？）最后base64写免杀马再反转回来拿下入口  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvSFwBT1o33fibvFBVBIniaib2Bfl9wqxooqsU1K8XibeYsPtNv3QwRYsPiag/640?wx_fmt=png "")  
  
  
      
  
  
至此，入口点打下，其实到这里已经打了两天了，因为是休息日打的，所以基本没有遇到什么防护。中间还有一些deapdump文件未授权下载，swagger，信息泄露等等漏洞，对后面拿入口权限没什么帮助也就没写，但为后面的内网打点提供了巨大帮助。其实一开始还找到一个任意文件上传接口，但是没返回，也就没了下文，后面看的时候，接口已经关了，说明还是有人员在应急，可能入口机刚好没有部署waf或者安全人员没及时响应，这也是企业通病，单靠人不可能24小时永远保持警惕。  
## 内网打点    
  
  
拿下入口，剩下的就是上cs，挂代理，进内网不在过多赘述。前面已经知道几乎无人进行安全响应，也就大胆直接上了，没在乎流量大小  
### 信息收集-没有值守就是莽    
  
  
通过外网mssql打开口子，挂上代理，丢netspy上去探测可达网段发现内网很大，存在2个c段1.1.1.0/24，2.2.2.0/24和一个b段3.3.0.0/16，几乎是全内网都可达  
  
  
先上goby探测内网服务，未避免流量过大，所以不开poc验证只扫描指纹，探测出大量资产  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvGNB0j8RBJlia0iaPurZuSB1ZXNxLjo38GCISkCr66wBcdHXrKNRJVBkg/640?wx_fmt=png "")  
  
  
### 永恒之蓝-总有没杀软的吧？    
  
  
发现大量445端口，用goby扫描单个漏洞，快速打点，先在内网站稳脚跟，虽然这个洞在17年就出现了，但在内网还是屡试不爽  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvaSmTLcD9IJkZWbOwlmpC1zg4UgkS9G0h9LFV8KTQjfcYdTkuHMVDIg/640?wx_fmt=png "")  
  
  
  
  
发现应该是有杀软的，有几台打不动，多试几台，拿下（总有几台是不装杀软的吧）  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvwnqMpkBNovzueyAySsRETSXVic9GIG1EZcWWYjBiaxibbpvMNUqs2aL5Q/640?wx_fmt=png "")  
  
  
  
  
后续继续尝试永恒之蓝，拿下4台内网服务器，差不多了就没有继续用永恒之蓝了，抓到密码，传免杀马上线cs  
  
  
抓了几台hash发现解出来都一个密码，写入密码本  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvIVa9Kl8vsjos8k2BvTNrbFeFgBwuoAIUjqXC6vdCAPXMLKrUz7ib7IQ/640?wx_fmt=png "")  
  
  
  
  
其中有一台很奇怪，能上线msf，但是执行不了命令，知道没人防守，直接远程上去一看，360企业版，但是设置的最低防护，也就能解释为什么能打下永恒之蓝但是执行不了命令了，关掉360上线cs  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nv6RmSCVNP2BmMVO3k21t0jt2QIXFtuPEnsjdiakPGN7ID6sgD5gFAyjw/640?wx_fmt=png "")  
  
  
  
  
桌面上还有一个navcat，那应该是有数据库的，直接导出数据库解密，拿到数据库密码  
  
  
成功拿下同网段数据库  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvJKES6btGmftvyEm3miaiaJHq61e9fc41icH80BLQEhRvXRJb8Q1RicBA2w/640?wx_fmt=png "")  
  
  
  
  
继续将密码放入密码本，可惜没有翻到别的东西  
### 内网横向-撞就完了    
  
  
当我发现内网其实比较薄弱的时候，就直接上fscan开扫了，速率开低慢慢扫  
      
  
  
开始横向内网，把所有上线cs的主机抓取hash，运气很好基本都是2008r2，可以直接抓到明文  
  
  
开始向两个b段开始喷洒  
  
  
上线了一批，然后注入到其他进程做权限维持，防止掉线，重复抓取hash，明文就丢进密码本  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvSgyE7h8icJqItmUIY5QX5ey6Lzmu7ibS7ET81bQsic6eRHlAciciaJENkow/640?wx_fmt=png "")  
  
  
  
  
然后发现横向不动，应该其中一部分有杀软，但是根据扫描的资产来看，差的太远太远了  
### 弱口令-企业安全一生之敌    
  
  
等了一段时间，fscan扫完了，一大波弱口+漏洞  
  
  
弱口令先拿下一波linux，没办法资产真的太多太多  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvMakicbwegKrXgeS5Yt7AHH0iaonzCfMcUVGveTLTeJMnr4pl3jXjd1og/640?wx_fmt=png "")  
  
  
  
  
然后是数据库弱口令拿下一波（一部分是密码本撞出来的）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvhVqSGNTRhiaIGfcpEH5eJ1oGn5hBgKERxFmzOaPZM83dJodA81zOsOw/640?wx_fmt=png "")  
  
  
  
  
但是很可惜的是，mssql跟redis几乎都不能执行命令，猜测是杀软拦截了，但是！峰回路转，有一台他就没有杀软，成功上线cs，在抓hash的时候发现，有域！且两个域控  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvjspicKSUcJJg5WAvcibOBH3qM2HoUZX9nASdB4Iap0aibMmicUMVUC3hjQ/640?wx_fmt=png "")  
  
  
  
  
先放着，继续看web漏洞，发现大量heapdump 未授权，nacos未授权，两个iis put 等等漏洞，先看能rce和密码泄漏的，将heapdump和nacos里翻出来的配置文件密码跟前面外网的一起加入密码本，能连的数据库连上  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvFpwXBnhSia9xbaydpWZYgJfJXSWOnaibAStTIAQzL8xAEJm8dMuPcoLg/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvszoar8UgkqYHibbs2H2c7TX3ib6bO3V84YG87JVaibANCyJnXx1nbf7nw/640?wx_fmt=png "")  
  
  
  
  
继续拿下2个iis put 跟tomcat弱口令，又拿下3台上线cs，用烂土豆提权拿下高贵的system权限  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvxYOTicDvug7cXS2Iiaib2ORHxiabVYvq3P0jyGVkU5gibFsTnREBUGzDBaQ/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvUsgvHiaaow6lzpZXibCeicB3YeycM70WBLGegJMjp5m0pqrGNycOKZjVw/640?wx_fmt=png "")  
  
  
  
  
还有很多危害不是很高，比较麻烦的都没打，哪有喷洒来的快啊  
### 拿下域控-免费比收费的强    
  
  
回到刚刚有域的mssql服务器，上线基本就是cs自带的提权或者土豆家族提到system，然后把上线cs的服务器，全部抓一遍hash，然后继续喷洒，上线一大批主机  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvUrsPicJERAjicxiaIImw0IUicWfc7UYQ9QsKX75B4RsX1YQibnjLApZwibzA/640?wx_fmt=png "")  
  
  
  
  
开始对域控进行横向，用那台域内的mssql服务器的hash进行横向  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvSIxdpMqKXg5IuJyiaia8E4wV3ibDBhT8z3cuOLJxRffeNH81YgT0z0CRQ/640?wx_fmt=png "")  
  
  
  
  
然后问题就来了，一直报错  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvrr5R1icDEiaiciaBDkibex9xvsBTKOicibtKpUt4ax2yITia9HQ7CC4o2vLc4g/640?wx_fmt=png "")  
  
  
  
  
以为是密码错了，将密码本内所有的密码，对两个域控高危端口进行爆破  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvibicf9LQiamSNxRXaibEc2yqTn0yfw8WCPYnrFdjjOmIoiccLxviaDvMa3Cw/640?wx_fmt=png "")  
  
  
      
  
  
明文密码没错，但是横向不过来，很奇怪，换了多个工具发现都横向不动，又打了下永恒之蓝，发现也没有，陷入僵局  
  
  
突然想着扫下端口，看看有没有其他服务可以入手，看到3389开放，其实没报希望，因为上面爆破445的时候爆破过3389了，没有爆破出来，想着手动试一试，没想到就这么进去了。。。。  
  
  
迎面而来的就是火绒+天擎，怪不得横不动  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvGonNCDMWlVWNzojYy6T75nLdpa9bicE620HN7awroUBZIKwzqwoepUQ/640?wx_fmt=png "")  
  
  
  
  
关掉火绒防护（天擎居然不拦截横向，收费的还没免费的强？），成功上线cs，这时候已经拿下域控了，看下域用户1000+  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvHB5sVwXYGwEGHLHquichoVSlYaIgFeN1ejwSjyIgQorOAbNXvSnaZsQ/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvdKWRKUTQNJwsvzVEHnxABDq307sYtaJrtbl8MIICPlp3DcaL7jt1dQ/640?wx_fmt=png "")  
  
  
  
  
然后继续拿着密码本爆破下数据库+3389，又是大量数据库  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nv1E3ic2go1yrs4U1gobMQY5jLAEnPGfpj7XAFbkBSEmdZhuwh6BAkhqQ/640?wx_fmt=png "")  
  
  
到此基本已经打穿完了，拿着密码本还能撞一波各种网络设备，堡垒机等等，中间也通过弱口令拿下一些网络设备，接管大量路由器交换机  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nvKBefEicPB85X8y5Dgw4cs98cAwgvtwP5LeFEXCcLclEud7qWRPGsTmg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmONLlXEU8Fm0NNvcxeI7F8nv56J9CRBwyAFpicqiazwSbFl9LsyELUfO34RCaMcmDJSjYHqKN3ozHI9g/640?wx_fmt=png "")  
  
  
## 总结    
  
  
运气好，有手就行  
   
  
  
  
b站视频讲解直达  
  
https://www.bilibili.com/video/BV1NemaYoEE6/?spm_id_from=333.999.0.0  
  
