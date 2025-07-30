#  代码审计 | 如何获取CVE漏洞编号   
原创 zkaq-yusi  掌控安全EDU   2025-01-30 04:02  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  yusi 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
前言：最近在网上找了套源码，想着练一下审计，也不能说有多深入，但是学习一下审计流程，源码下载在文章末尾  
## 环境搭建  
  
直接用 phpstudy 搭建就行了，选择一下路径和端口，然后新建一个数据库，把目录 Database 下的 sql 文件导进去，再简单配置一下 /rental/db_connect.php 文件以连接数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf33MAmCyWJlibR08rHF0KazJmxqNnsfAibV3lgtT3uibB0hb90nevIEmYcQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
访问端口页面如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3mDIrsIuIary56n3afhHdRuzhZdDhYVko0xA6wpyGzIpPiccvwiah1hQw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在 Username and Password.txt 文件给出了默认账号密码，登录后可以简单看看后台功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3WQvb7LCFSUYa44fG1U2WEhk4hHl4wiaBg0P9iavgZq2MuE4aNMHO5Iug/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 工具扫描  
  
既然有源码肯定不会去挨个功能点的进行测试，掏出 seay 自动审计一手  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3oNFnpLARFu6Sjg6VxhdegBMey0m1YICOiaTfvqqDicIzJEib3t4vNia3PQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
看到显示漏洞挺多的，具体存不存在还需要跟进看看，因为有些可控参数是加了过滤或转义的。再用昆仑镜扫描一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3P72xrXqBlQ2TZ10p9MJWqHLB6LCVnt2I2XH5E4Jeia7ZTw419OeP3uA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
也基本上是 sql 注入漏洞，至于变量覆盖一般不太好利用，不是关键时刻不用看。  
## 漏洞分析  
### sql 注入  
  
上面显示的 sql 注入漏洞最多，就先分析这个，直接跟进到 /rental/admin_class.php 文件。在其登录函数 login() 发现 sql 语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3ogkd8GuOO6MP8Zjib5ia4FrjLQT9NIY8micmowSQaylo8tiab0BCwBXHMw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
$username 没有任何过滤，直接就拼接进去了，属于是甩脸上了。由于没有回显查询结果，直接时间盲注就行了。  
  
稍微更改一下代码，测试一下，构造  
  
```
1' or if((length(database())>1),sleep(5),1)#
```  
  
  
看到我们的参数已经拼接进了 sql 语句，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3AI2TOcY0Dicd5SCKStOia2d0fShxWX8Vpic0e236MpYiazcUhNZdnszqNA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
回到 bp 发包也能看到盲注成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf30A9omjWCakWAooSTrTdVnLo7L6s5NoEVibAUIgX1XFUXRniaWqucjibjg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
类似的 sql 注入漏洞还有很多，就在 /rental/admin_class.php 文件中，一抓一大把，如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3DZt2RlEWTX03KI17UKicMgNbp5D45m5R17amJnDyFaxk37X1DLmfB9w/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf35Jlexc9mBd7AlGcSSg9ibdDbiaEhhic14bicyHTCRAWHO9biaTMQDL0nTfQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
都是没有对参数进行过滤处理造成的 sql 注入。但是这些函数对应的都是后台的功能点了，在实际应用中没太大用处，还是登录处的 sql 注入危害最大。  
### 文件上传  
  
继续审计，发现存在存在文件上传点，有三处都有下面的相同代码逻辑。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf39aJdNXNSsI7wX0eZOPbukv6VYTUvic3Yt0VF84jr3jmrUZ8E3pflsqw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
会先上传生成个临时文件，然后利用函数 move_uploaded_file 来把文件移到目录 assets/uploads/，看到对文件后缀和内容都没有过滤，然后文件名中的时间戳可以根据时间范围爆破出来的。  
  
但是在后台功能点找了半天也没发现文件上传的点，应该是函数默认的参数里根本就没有它，那么直接自己构造，这里就拿 signup() 函数来测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf365nP4ia6qDHrhuXSXplkdTv7gv3t8NaNajBm2jB1JvxYg5RTb9YfcsA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
构造好后发包，发现报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3ScFB8yWc7g6xXS11pBwTnB7N1T2HbuyJ6ibCnIeadVqmnMLsic04HicpA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
显示无法移动文件，调试看看原因  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3Py22TNicFavHWVTdGPTicDoNjGrLCEJn2VZCicDsTwSJfmDz1UUu7Qzow/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
看到临时文件在 C:\Windows\ 目录下，用记事本查看内容显示报错：“文件包含病毒或潜在的垃圾文件”，到这里其实我大概已经知道原因了，又是系统自带的安全保护在作怪，将其关掉。然后再次上传，成功上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3DoU53eIpt539Nm1v3FQSlmjDSHUXE0poSASGubfpzxaRHgs14ice4pQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
访问木马即可 getshell。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3lAQcicNz2Z9frClTBIP6WB6LIqmysXaFBEZq0J78bN8PCJMaaWtPg7w/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
本来以为凭借 sql 注入 + 文件上传就能直接拿下该系统 shell，但是离谱的来了，发现该系统根本就没有鉴权，不用登录直接构造 poc 就可以实现上传。  
## 总结  
  
只是一次简单的审计经历，站点也是漏洞百出，甚至鉴权都没有。不过拿来熟悉熟悉审计流程还是不错的，最后去 cve 平台上搜索发现还有没交的洞，这洞都贴脸上了，于是顺手获取了几个 cve。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3u39icVibt5yK3UsDSGk2PxczDtwKqEMD708aAHQv6Axcb2KEiaR85wIFw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqd4X69bILaYK5BzUECRRf3LgqJ9RibYRhdsSE381YBBvapJa5z7bmKkwhIuRX2NMFBGg9ich6rha8g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
源码地址：https://www.sourcecodester.com/download-code?nid=17375&title=Best+house+rental+management+system+project+in+php+  
  
最后祝大家都能获得自己的 cve  
```
```  
  
  
