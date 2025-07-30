#  PbootCMS历史漏洞分析 0x01   
原创 数据安全实验室  山石网科安全技术研究院   2022-09-14 11:28  
  
‍  
# ‍  
  
V0.9.8  
  
php代码审计的初学者，所以就先从D类CMS入手。  
  
后台默认账号：admin 密码：123456  
  
代码审计分：  
  
·  
危险函数追踪流  
  
·  
通读全文流  
  
·  
黑白盒结合审计流  
  
  
**开发者标签手册**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbMfWAxFHeuuL5OdcK8VflBRUqsvtxtEkXKzIS4icFqu3drTYD0YfC4ptPUeUKQwO6iaCOtxGk4uUg/640?wx_fmt=png "")  
###   
###   
  
**IF条件语句**  
  
### 注意：条件语句中字符串需要用单引号或双引号，条件也可以使用原生PHP代码；所有对其它标签的调用都为字符串，需要加单引号。  
  
```
```  
  
  
  
示例一：在IF  
中使用PHP  
函数示例：  
  
```
```  
  
  
示例二：  
高亮栏目示例：  
  
```
```  
  
  
示例三：嵌套  
IF  
：  
  
```
```  
  
  
这里说了可执  
行PHP语句，但要插在IF条件标签，例如：  
  
{pboot:if(php语句)}{/pboot:if}  
  
然后再返回文件查看源代码文件：  
  
该文件是：标签解析引擎控制器，也就是解析标签的。  
  
代码的1273~1314为关于IF条件语句的。  
  
/apps/home/controller/ParserController.php  
  
```
```  
  
  
关键在   
  
```
```  
  
  
只  
经过简单的正则匹配之后就赋值，然后  
eval()  
执行。  
  
到此需要寻在利用点。  
  
**Poc**  
  
##   
  
Poc:  
  
{pboot:if(phpinfo())}!{/pboot:if}  
  
最后经过寻找，只要发现后台能编辑的地方，基本上都能插入IF条件语句标签并能解析执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbMfWAxFHeuuL5OdcK8Vfltic1qrNd9pVSrXMLzia4K147XPuYuy0bpiaC5QUFdKadGAyYPibsT9Ria0Q/640?wx_fmt=png "")  
  
访问首页就可以看到  
phpinfo  
页面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbMfWAxFHeuuL5OdcK8VflNaLYTaEMcMdCmbQgbuSB6jADaSGhM12RV7RyCQv9SCHhAaBLoWEUwA/640?wx_fmt=png "")  
  
然后尝试了多次多点均能Getshell。  
  
**另外**  
  
##   
  
前台某处存在CSRF，利用其修改后台内容，但均有提升修改成功的页面，做不到无感知修改内容，因此CSRF+IF条件语句标签也是比较鸡肋。  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSbMfWAxFHeuuL5OdcK8VflcWSiaickBgic6MDWCcZtQOhmQuvH5rqfCdCdOZUQEo9kknF3HZ5aozBfQ/640?wx_fmt=png "")  
  
  
  
‍  
  
‍  
