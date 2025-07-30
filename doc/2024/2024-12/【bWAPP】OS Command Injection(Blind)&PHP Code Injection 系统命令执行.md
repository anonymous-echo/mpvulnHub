#  【bWAPP】OS Command Injection(Blind)&PHP Code Injection 系统命令执行   
原创 儒道易行  儒道易行   2024-12-15 18:00  
  
**那天下着很大的雨，母亲从城里走回来的时候，浑身就是一个泥人，那一刻我就知道我没有别的选择了**  
## LDAP Injection (Search)  
  
LDAP 全英文：Lightweight Directory Access Protocol，翻译过来就是轻量级的目录访问协议。其实就是访问目录，浏览目录。有很多企业存储一些数据信息，例如部门信息，部门里成员的信息，公司的可用设备信息等，这些信息单独放在类似于网站的那种数据库中的话，会显的有点大材小用，而把它们放在目录中，文本中最合适。好比在文档中搜索指定的内容，在目录中搜索指定的文件一样。 LDAP 也有自己指定的语法，也可理解为它是一个存储信息的数据库，为了搜索方便，很多网站提供了其查询的接口，和普通的搜索框无异，对于指定的搜索内容，在没有严格过滤的情况下，便可以造成LDAP 注入。  
## Mail Header Injection (SMTP)  
  
通常的做法是网站实施联系表单，反过来将合法用户的电子邮件发送给消息的预期收件人。大多数情况下，这样的联系表单将设置SMTP标头From，Reply-to以便让收件人轻松处理联系表单中的通信，就像其他电子邮件一样。  
  
不幸的是，除非用户的输入在插入SMTP头之前被验证，否则联系表单可能容易受到电子邮件头插入（也称为SMTP头注入）的攻击。这是因为攻击者可以将额外的头部注入到消息中，从而指示SMTP服务器执行与预期不同的指令。  
## OS Command Injection  
  
漏洞url：  
http://range.anhunsec.cn:82/commandi.php  
### Level：low  
  
payload：  
www.nsa.gov  
;whoami  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7bNXjyfmq65zObicAIcm8aHkToz3tn5yK5tzmV7DZkYUZCvrpNGXf5cQ/640?wx_fmt=png&from=appmsg "")  
  
原理：在DNS查询之后再执行dir命令  
### Level：medium  
  
查看源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7WoBkGCrDaF1KasoPiaiaSeshpyM0R8XqY7rhqO3tlvU7ouDTicibSJgnnA/640?wx_fmt=png&from=appmsg "")  
  
commandi_check_1是把&和;替换了，还可以使用|  
  
构造payload：  
www.nsa.gov  
| whoami  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7Yjua25gEQgT3IvRCfQcWfskZLaGRic8uCyHFJVIMWv82HngiaRHdhK6Q/640?wx_fmt=png&from=appmsg "")  
### Level：high  
  
查看源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7iapFDm72zX31mfC2uet3OndTN56v5WtUnLXbpv5nXGZON1dVgrv42sg/640?wx_fmt=png&from=appmsg "")  
  
escapeshellcmd()函数用来跳过字符串中的特殊符号，防止恶意用户通过不正当方式破解服务器系统  
## OS Command lnjection - Blind  
  
漏洞url：  
http://range.anhunsec.cn:82/commandi_blind.php  
  
命令盲注就是注入后没有返回信息，要根据反应时间判断命令是否成功执行  
  
输入127.0.0.1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7SELkxuoulcnhESZShaNTcQeicACR4kYvLEXSOAwTj0icVAyvxuVozFxA/640?wx_fmt=png&from=appmsg "")  
  
输入  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7WibH6hEbgGJWzxT7pKWADIFeAtsSacjPjjUdhtgdayfuZxiblhKCwIdw/640?wx_fmt=png&from=appmsg "")  
## PHP Code Injection  
  
漏洞url：  
http://range.anhunsec.cn:82/phpi.php  
### Level：low  
  
构造payload：?message=phpinfo();  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7nrSN9ibKa6icmKz3wJqxpVglLqDxqotia1o6Af5LM1Fl91gbMdIyx4abA/640?wx_fmt=png&from=appmsg "")  
### Level：medium&high  
  
查看源码，使用了htmlspecialchars()函数无法绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7Ek2OR0W8SRLy05esLauGyqcPfmQbBvWpJ6ZNicalyaId469ljNXT01A/640?wx_fmt=png&from=appmsg "")  
## Server-Side Includes (SSI) Injection  
  
SSI是英文"Server Side  
  
Includes"的缩写，翻译成中文就是服务器端包含的意思。SSI是用于向HTML页面提供动态内容的Web应用程序上的指令。它们与CGI类似，不同之处在于SSI用于在加载当前页面之前或在页面可视化时执行某些操作。 为此，Web服务器在将页面提供给用户之前分析SSI,可在SHTML文件中使用SSI指令引用其他的html文件（#include），此时服务器会将SHTML中包含的SSI指令解释，再传送给客户端，此时的HTML中就不再有SSI指令了。Server-Side  
  
Includes攻击允许通过在HTML页面中注入脚本或远程执行任意代码来利用Web应用程序。  
  
一种对于这类漏洞的挖掘方式即是查看.stm，.shtm和.shtml的页面是否存在，但是缺少这些类型的页面并不意味着不存在SSI攻击。  
  
默认Apache不开启SSI，SSI这种技术已经比较少用了 IIS和Apache都可以开启SSI功能  
  
核心代码  
```
```  
  
防护代码  
```
```  
#### low：  
  
low级别，没有防护，能xss  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7rEUlLPCnnysYXuwsgKKOZGe0mq7Ff3PK3zYtlnknAnLIicluhVwTDxw/640?wx_fmt=png&from=appmsg "")  
#### medium：  
```
```  
  
addslashes（）在符号前加反斜线  
#### high:  
```
```  
  
将预定义的字符装换为html实体字符  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpyJPHZhfhpZ9Yy54E9WD4w7pS29S82DicSq7Y3ZCNhOMrAASoiaedIUedwtPzmM1v1BLEsicLEKSHULQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
