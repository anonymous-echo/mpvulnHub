#  【漏洞文字】博斯外贸管理软件 SQL注入   
原创 1ang  小羊安全屋   2024-12-25 09:01  
  
导言  
  
  
文章仅用作网络安全人员对自己网站、服务器等进行自查检测，不可用于其他用途，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。切勿用于网络攻击！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/reg3T0Fqiax8lPLzcDQicIfv49r4EgibnRuz10rNYiaBDlUaSfqrWgYrD36DPE4uiar4kHLq7x60wPaguey7Pz8BTOA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
PART   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ktKCAuwAa8dmj6TprnPZe7wiasyw7EtyLyNy649qJ3lfwTtxWSKPhdzSJ7JicAxfkYSlAawXNCOmzhS3Rib2ZradA/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/bBPjSTVLnXbhGFgqz3CwuWdGELjD7wYzxM9mrvz9tUBAwaeMof26ca9fSicRezRV3vKt7a04AfuPcLoVBtgpYDw/640?wx_fmt=gif "")  
  
漏洞描述  
  
博斯外贸管理软件V6.0 loginednew.jsp 接口的account参数存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/3RSJOISXa6jxhSggXrE9ibwcuRuSia2kIsFAHRbtYf5eb0O4TtXqn4yweC65OpzNRdrrnrkEYbjdqUkg9eIQVkHA/640?wx_fmt=gif "")  
  
漏洞复现  
  
漏洞URL：/loginednew.jsp?welcome=&systemname=BS&account=1&password=1&val=0000&availHeight=834&Safari=Y&loginurl=  
  
漏洞参数：account  
  
漏洞详情：  
  
1、打开自己的服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lnzwRq0p4icHSYVCuJKhjq1buoLTicFTJ9dcrWhGUAy4VnVAZQiatcicpshEpTDiayRrrVh4pGZYgDtfhQTwrhibT5Zg/640?wx_fmt=png&from=appmsg "")  
  
2、漏洞验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lnzwRq0p4icHSYVCuJKhjq1buoLTicFTJ9WJPdS1yGeibDT20MN5Z5lRYbr7n34rx5ccrmBtiaVEDicjGPsHicUWibC4A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lnzwRq0p4icHSYVCuJKhjq1buoLTicFTJ9JogdViapUiaor36WhF8LWc5md3Njw0xoUcBaeek0JOiadbvGPlgcGuUeA/640?wx_fmt=png&from=appmsg "")  
  
  
END  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/bBPjSTVLnXbhGFgqz3CwuWdGELjD7wYzxM9mrvz9tUBAwaeMof26ca9fSicRezRV3vKt7a04AfuPcLoVBtgpYDw/640?wx_fmt=gif "")  
  
修复建议  
  
1、升级系统至安全版本；  
  
2、禁止系统对外开放，或启用白名单访问。  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3YqocLTzbGQjus64G8bmAyDCiaaE8IY57OmvR7bHq1UzAqRG0gme38uvdXggrrlmNJyePh4Ox1AI9oQ1PY8otRw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zQTAicxBBI1QaAzOgiblQicVnO8XZUWj6cpdOL8EHU0unLP9fGEBxdTZDXfHeeEGGibNzMYfxDgtyicKv8r5Q18UsyQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibpQMTribKicf2Xibe2qFYgtMw8UhDdllzZryYjianfS4LcHCAT7VWbjwoaZNF4lCAxUmFdIibmUrBibToxxt9QbGf3WQ/640?wx_fmt=png "")  
  
因文章不能出现POC、会导致文章被删除。  
  
个人星球，欢迎加入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lnzwRq0p4icF88zkXzrnATODaPrYYSZ1ZUyicl3UZSdda9RxiavwPXEWfdn5WiboAA7HiavEZblfA9CLsFQKlxsU8Xg/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2TVkuiaNYQGjWwnsmctvTmClxYzHJicxBiahOibtjQicH8vaCz7TPFMK0EsiczbQfwzlSNiaaU8akYibuIdpUCicYoFGZNQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1C21KZjMBaSHgMAvP4faiar3XTekytaNKOlc7UibOhTqxaA0iapiabBKVITYicR4NM125QTp9lYt9lylfI7LzfqkLsg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uNpMBR1pZOia18Kuib6Qukssk36955zGygr0vKFbclQLHMRSJqic5s7waKZlJrto2oTb42sYY7icxo5zcn24MjDSfA/640?wx_fmt=png "")  
  
  
  
  
**——The  End——**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iaZREh6DtDyA9wcDsp0m1RNV9C4uiaagltPDn83s3k6Sw5DbfRWdGc25Q1WDNCpjZLXQpCxFfiaGT5ag/640?wx_fmt=gif "")  
  
  
  
  
  
