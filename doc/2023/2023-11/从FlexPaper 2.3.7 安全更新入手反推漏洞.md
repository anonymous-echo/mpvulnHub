#  从FlexPaper 2.3.7 安全更新入手反推漏洞   
 船山信安   2023-11-26 00:00  
  
## 前言  
  
FlexPaper是一个开源轻量级的在浏览器上显示各种文档的项目。它为Web客户端、移动设备和平板设备提供了文档查看功能。FlexPaper使在Flex中显示PDF成为可能。这个过程无需PDF软件环境的支持。它可以被当做Flex的库来使用。  
  
另外使用者也可以通过将一些例如Word、PPT等文档转成PDF，然后实现在线浏览。  
  
FlexPaper发布了2.3.7版本，此版本是一个安全维护更新版本。该版本中修复了wordpress-redtimmysec团队发现的一处无需身份验证的RCE漏洞以及两处未公开的xss漏洞  
## 漏洞分析  
  
我们首先通过diff2.3.6版本与2.3.7版本，查看下修改的文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbia0ibhzQ9z9stSicnMV72LbU0oMXVztma6se2giaHTcmT7vHUacJK3B5ljw/640?wx_fmt=png&from=appmsg "")  
  
可见一共有7个php文件被修改。经过分析，除去mudraw_php5.php与view.php，其余5个都是安全更新。  
  
这些更新可以分为主要用来修复三个漏洞，具体见下文  
### 任意文件删除导致RCE  
  
php\change_config.php存在如下更新  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaykpl77hdtYN86AsdyTYukF8N1KlUKPaJe647EZ9IsDjFOaxkDYyqxg/640?wx_fmt=png&from=appmsg "")  
  
在change_config.php中，7-11行新增了一个权限校验模块，19-22行新增了一个setup.php文件存在性的判断  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbia2rJvuiam2gnwN0uSWfpfdRBJsv9IdupwweoSVw5zpdia9NuGxEYWsCjw/640?wx_fmt=png&from=appmsg "")  
  
在46-47行间新增代码块中，由原来的删除$dir目录下所有文件，改为删除swf png以及jpg文件  
  
根据此处的更新可以推断出change_config.php中存在的漏洞可能有两处，其一是未授权的访问，在2.3.6版本中change_config.php文件首次管理员身份校验位于54行处，而不是文件开头，如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaYSu1icibWJujrPWjOGOAeGibcdeeWHmmqmCzq5zLkAVU8p90IysT8VE9w/640?wx_fmt=png&from=appmsg "")  
  
这也就意味着，在2.3.6版本change_config.php的前53行代码，皆可以无需身份验证而访问执行  
  
接下来分析下前53行，有没有可以利用的点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaVKxXkCJRAhn2xYSmYuxkTURqXnts80E3XNM7j9JURQ1S8rTtqkJLhg/640?wx_fmt=png&from=appmsg "")  
  
在如上图47行处，存在一处unlink方法，该处删除$dir指定目录中所有文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiazsZE7yoAsYKvQKUUKtv7H04vKS0eibfs4OtiarbRiacqe8jTMBibDHY9Fg/640?wx_fmt=png&from=appmsg "")  
  
$dir变量为系统中存放swf文件的路径，该值由$configManager->getConfig('path.swf');得来，getConfig方法简单来说，就是从上图第一个红框里$configs变量里取出对应key对应的值，而$configs['path.swf']又是由$path_pdf_workingdir变量传递而来  
  
接下来我们查看下$path_pdf_workingdir变量是否可控。仍然在change_config.php中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiakLAmcOw1FqOQhGWgicP0dgkicUPgoJUUs9SA6JEBVEMdVMEB517VuibZA/640?wx_fmt=png&from=appmsg "")  
  
可见POST提交中存在SAVE_CONFIG参数时，即可通过POST提交SWF_Directory参数来赋值$path_pdf_workingdir变量，从而直接控制上文中需要使用unlink清空的$dir目录  
  
通过change_config.php提交的更新内容以及对2.3.6版本代码的分析可以得知，未授权用户可以使用change_config.php提供的功能，通过POST提交SWF_Directory参数来清空任意文件夹中的内容  
  
接着来分析change_config.php中第二处更新  
  
change_config.php中的第二处更新如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaVcMcWPrguDR8MxGeraOzCvrR0DncxF4AM3XrljIh1t3dY1ZfPmp6zA/640?wx_fmt=png&from=appmsg "")  
  
加入了setup.php文件是否存在的判断的代码，当setup.php存在时则报出"Please deletesetup.php file in your flexpaper/php directory to access the FlexPaperconsole."并且exit。与之相类似的，在Index.php文件中也有类似的检查  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiayfR1ZUjXq9mMCjzIS7BVrPRtS7ujAPNXoxeZh70xQR99zd61gb3HPQ/640?wx_fmt=png&from=appmsg "")  
  
“Set up has completed. Please delete the setup.php file in your flexpaper/phpdirectory to access the FlexPaper console. Refresh this page when done.”  
  
提醒用户安装结束后删除setup.php，但Index.php文件并没有强制exit程序  
  
这些线索全都指向了setup.php，setup.php其实是flexpaper后台的安装程序，主要用来生成以及配置配置文件  
  
从上文分析的未授权任意文件删除以及删除setup.php的提示来看，此次rce漏洞一定是由任意文件删除从而导致系统重装，在重装过程中setup.php安装程序存在一定的安全隐患导致了rce漏洞的产生  
  
接下来看下setup.php在此次漏洞中担当的角色  
  
在setup.php中首先发现了如下两个个方法pdf2jsonEnabled/pdf2swfEnabled  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbia1ocic4eg8KcUJHWHRpBZDGQM74YcbWBnchicx3PtQO4CQDwvk5RQWWcA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaxiaTmic43ap66micOlkfTzwGC2qh9hMuQWXSBryyRgIL5eYtsqp2ibpZpQ/640?wx_fmt=png&from=appmsg "")  
  
这两个方法调用exec将传入的变量直接执行，如上图红框处  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaexDziamU5oJHlYnAapK2wSRkP2fiaDckcSX5j1SeO0z1hWicnIJxQIRaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbia2agVhxyHrRCtD1OFZBbjNEprG02F2kTcCLZe2ibZ5JL5ibyw4WLHErnw/640?wx_fmt=png&from=appmsg "")  
  
在setup.php中，程序多处调用这两个方法，如上图而传入这两个方法中执行的$path_to_pdf2swf与$path_to_pdf2json变量竟然直接可以从GET请求中传入，见下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbia9mZelBHQuiaiasOJMOgaQYbRQm4GbptOt3SN7xrhC6cmul7VPRibj3y4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaIbDJsZjiaXeicwJhnRgNB1Q7eHkA4f5HPia2g76QPEAvyhRhRicAYCtibJw/640?wx_fmt=png&from=appmsg "")  
  
setup.php这个文件自身的访问并没有什么限制，只要setup.php文件存在，就可以被任意用户访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbialMOsSjvlM0sKWqUNMym0UPXeYsANL0zep3ImMLM7MmzYTGBZVoJQ2g/640?wx_fmt=png&from=appmsg "")  
  
但是在setup.php中，存在如上图代码，会检测admin.password是否为null，来判断系统是否已经安装成功，安装过的系统将会直接触发exit，退出安装流程，也就无法执行后续我们任意代码执行的地方  
  
admin.password这个配置来自于php\config\config.ini.win.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaglOWUOEWQiajJHXyib1mCCjNic96TSXwMytR8hNB0h1PaejkGTMhC8Q9w/640?wx_fmt=png&from=appmsg "")  
  
安装前如上图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbia83KxzNgK5eAOJ0J0k0WSUSTnkl2NyaH2t3LfMyc0QsATzZOPrRG5xg/640?wx_fmt=png&from=appmsg "")  
  
安装后如上图所示  
  
配合任意文件删除把config目录清空，即可成功触发重装机制，执行setup.php并且通过GET请求中PDF2JSON_PATH或PDF2SWF_PATH参数传入payload，造成任意代码执行漏洞  
### simple_document.php中反射型XSS  
  
php/simple_document.php 存在一处更新  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaRzpZicKqS82jx1HgSJM67SgqCicC9hoHZDwUBTibLQMicwvmOialDWVic1QA/640?wx_fmt=png&from=appmsg "")  
  
可见，使用htmlspecialchars将GET请求传入的doc参数过滤  
  
接着看存在问题的版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbialLXW5zbtdTaghKAL6j8zt56aLOkVAwfEDXg0uwhMwxY4sekTmwHIaA/640?wx_fmt=png&from=appmsg "")  
  
这里直接将GET请求中的doc参数echo，从而导致了xss漏洞的产生  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaGpE52xXRibZqRsYT5sUvaWWu3k8UUG7jTOM8P9ju7UAjJFbIdXkFXGA/640?wx_fmt=png&from=appmsg "")  
### split_document.php中反射型XSS  
  
php/split_document.php中存在如下更新  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaCO2W0lIQny6xrBUN4GibRcB1NfNChZ7qcauicd6XsppQ7jCc5r5lIEeQ/640?wx_fmt=png&from=appmsg "")  
  
上图可见，更新后的程序使用htmlspecialchars将GET请求传入的doc参数过滤  
  
接着看存在问题的版本代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaEoy6ugefl6NzjE1t0Z3aicgxapCA9flOIic2uol9n3zaiaMZfUsmNgjwA/640?wx_fmt=png&from=appmsg "")  
  
漏洞成因和上一节的如出一辙。但是这处都漏洞利用难度很大，原因如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiafgdIrqPKjGFsY6gia0FXDYkYiacJa2IcShXcAt2zialic0vjkWkoOcYVDA/640?wx_fmt=png&from=appmsg "")  
  
见上图红框处，存在一处getTotalPages方法，该方法接受我们传入payload的$doc参数作为pdf文件名，拼接pdf路径。  
  
跟入getTotalPages方法，如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiakIJRrkMzfMplB6A12FXicAPGkJ0kRxxlUvQCZny2yibckqwSas6m5gpA/640?wx_fmt=png&from=appmsg "")  
  
在该方法中有如下判断：如果fopen或者fread传入的pdf文件失败，则返回false。这将导致我们js中numPages变量为空  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaXENPaWwNjPvropJPWgq9AZCtsE3UDubibttAHJU0dnGg4M6mQ5ht3LQ/640?wx_fmt=png&from=appmsg "")  
  
实际利用时，我们需要造一个payload，这个payload需要与pdf文件路径中的一个pdf文件的文件名相符，这点利用起来比较复杂。  
  
如果没有满足这个条件，则会出现如下错误: numPages = ;  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiay6qyOmwjWzu0Q5O1O9Kt7m7lXicwE7UU8xRUywjBUchPCIYp6Qhpp2A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNkaKlJfwUCF4kXTGtTvfbiaz3EHcgpxwjFNEhUEwcKnRN1HVsnaFjq4pgI6icaTZqnxKBsc4oDheKg/640?wx_fmt=png&from=appmsg "")  
  
Js脚本无法成功执行，xss不能稳定复现因此此处的漏洞利用难度比较高  
## 结语  
  
FlexPaper作为一个开源项目在互联网上非常流行。据相关资料显示，至少在2014年之前，维基解密一直在广泛的使用该组件。但是从本次漏洞来看，其安全性仍有待需提高。关于本次漏洞的分析，在寻找存在漏洞的3.2.6版本花费了我一些时间：官网在github上的更新终止与2.2.7版；官网上没有关于旧版本的下载链接；FlexPaper3.2.7发行说明中丝毫没有提及安全相关的改动。花费了好久，最终才在一个下载站找到了3.2.6版本的源码。  
  
来源：https://xz.aliyun.com/ 感谢【  
熊本熊本熊  
】  
  
  
