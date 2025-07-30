#  PHPGurukul Men Salon Management System最新SQL注入漏洞及解决方法   
原创 护卫神  护卫神说安全   2025-04-24 02:28  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEia7sYdxLRWjXZvASZchUkqRjOsZ8sPyuDWmUPJIYr8ibMnV9WH3ZMiaK5BdfS2IuhzWMuOibqRbAKoXQ/640?wx_fmt=png&from=appmsg "")  
  
PHPGurukul Men Salon Management System 是一款基于 PHP 和 MySQL 开发的男士美发沙龙管理系统，系统功能涵盖发型师管理、预约管理、订单处理等，旨在提升沙龙运营效率。  
  
  
CVE安全漏洞共享平台于2025-04-07公布该程序存在SQL注入漏洞。  
  
**漏洞编号**  
：CVE-2025-3370  
  
**影响产品**  
：1.0  
  
**漏洞级别**  
：  
高  
  
**公布时间**  
：2025-04-07  
  
**漏洞描述**  
：在 PHPGurukul 男士美发沙龙管理系统（Men Salon Management System）1.0 版本中发现了一个被归类为高危的漏洞。该漏洞源于 /admin/admin-profile.php 文件中的 contactnumber 参数，对输入的数据安全过滤不当，导致不法分子可以利用此漏洞发起SQL 注入攻击。  
  
  
  
**解决办法：**  
  
该漏洞存在于后台，因此可以使用两种方案解决：  
  
1、对全站做SQL注入防护  
  
2、对后台做保护，禁止未授权人员访问。（不法分子不能访问后台，自然也就没法触发 /admin/admin-profile.php 的SQL注入漏洞了）  
  
可以使用『护卫神·防入侵系统』的“SQL注入防护模块”和“网站后台保护模块”来解决问题。  
  
  
  
**1、SQL注入防护和XSS跨站攻击防护**  
  
『护卫神·防入侵系统』自带的SQL注入防护模块（如图一），除了拦截SQL注入，还可以拦截XSS跨站脚本（如图二），一并解决PHPGurukul的其他安全漏洞，拦截效果如图三。  
  
  
![PHPGurukul防SQL注入](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEia7sYdxLRWjXZvASZchUkqR1MsQ5HsepFuZBuB6PrQNMZraaib0xtYIbsCDHyUlLmt2iaHr5nT4rwHQ/640?wx_fmt=png&from=appmsg "PHPGurukul防SQL注入")  
  
（图一：SQL注入防护模块）  
  
  
  
![PHPGurukul防XSS攻击](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEia7sYdxLRWjXZvASZchUkqR8V38pJKtst8sExygwAp4rhHiaibiaaSlaYojXu3xNcPLetaD9LCsvrjxg/640?wx_fmt=png&from=appmsg "PHPGurukul防XSS攻击")  
  
（图二：XSS跨站脚本攻击防护）  
  
  
  
![SQL注入拦截效果](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEia7sYdxLRWjXZvASZchUkqRzgQRJzdJn5VKtprmzlzIAepEdCd6FCsq76vWPAImdg862XW2bib4nOA/640?wx_fmt=png&from=appmsg "SQL注入拦截效果")  
  
（图三：SQL注入攻击拦截效果）  
  
  
  
**2、网站后台保护**  
  
『护卫神·防入侵系统』的“网站后台保护”模块，可以对后台进行保护，只有授权区域或输入授权密码才能访问后台。  
  
如下图四，只需要输入后台地址、授权密码，就可以了。  
  
![PHPGurukul后台保护](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEia7sYdxLRWjXZvASZchUkqRoT6uBugaSz6DXNZyIw7REpC45qoHt5fTdEdnepY7CufEecmibSVEw9w/640?wx_fmt=png&from=appmsg "PHPGurukul后台保护")  
  
（图四：PHPGurukul后台保护）  
  
  
  
设置好以后，访问后台时需要先验证授权密码（如图五），只有输入了正确的密码才能访问。  
  
![网站后台保护](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEia7sYdxLRWjXZvASZchUkqRjpuHrfL22AW6TPUnrWbeiaucBmB56UQJHQ8Mlg9Le1JH6CQCG9V23tQ/640?wx_fmt=png&from=appmsg "网站后台保护")  
  
（图五：访问后台需要输入授权密码）  
  
  
