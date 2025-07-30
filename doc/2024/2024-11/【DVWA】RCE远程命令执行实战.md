#  【DVWA】RCE远程命令执行实战   
原创 儒道易行  儒道易行   2024-11-22 18:00  
  
**遇到挑战跟挫折的时侯，我有一个坚定的信念，我可以断气，但绝不能放弃**  
## 0.Command Injection(介绍)  
  
**命令注入（Command Injection）** 是一种安全漏洞，攻击者通过将恶意的命令插入到应用程序或系统的输入中，从而执行未经授权的操作。它通常发生在应用程序允许用户输入某些参数，然后将这些参数直接传递给操作系统命令执行时。由于输入没有经过适当的验证或过滤，攻击者可以通过精心构造的输入，在系统中执行任意的命令，达到控制目标系统的目的。  
### 常见的命令注入攻击方式：  
1. **系统命令注入**：例如，通过 Web 表单或 URL 中传递参数，攻击者可能让程序在服务器上执行特定的操作系统命令。  
  
1. 例如：如果应用程序允许用户输入文件名，并将该文件名传递给操作系统进行处理，如果没有对输入进行充分的验证，攻击者可以注入如 ; rm -rf / 的恶意命令。  
  
1. **SQL 注入与命令注入的结合**：有时候，命令注入与 SQL 注入配合，攻击者不仅能修改数据库内容，还能通过操作系统命令进一步控制系统。  
  
1. **Web应用中的命令注入**：很多 Web 应用会调用操作系统的命令或脚本，如图像处理、日志清理等，如果输入不受限制，攻击者可以插入命令。  
  
### 常见的攻击方式：  
- **注入恶意命令**：通过在输入字段中添加操作系统命令的分隔符（如 ;, &&, ||, |）来组合并执行恶意命令。  
  
- **文件操作**：注入命令来修改或删除系统文件，或者执行远程命令。  
  
- **创建反向 Shell**：攻击者利用命令注入漏洞，启动一个反向 Shell，通过目标机器与攻击者的机器建立通信。  
  
### 防止命令注入的方法：  
1. **输入验证和过滤**：对用户输入进行严格的校验，特别是过滤掉特殊字符（如分号、管道符号等），限制用户输入范围。  
  
1. **使用参数化命令**：避免直接将用户输入拼接到命令中，使用安全的 API 和函数（如 exec、system 等）时，传递参数而不是构造命令字符串。  
  
1. **最小化权限**：限制应用程序和用户的权限，避免使用高权限账户执行命令。  
  
1. **环境隔离**：使用沙箱（sandbox）或容器化技术来限制命令执行的环境，减少潜在危害。  
  
命令注入是一种非常危险的攻击方式，因为它能让攻击者执行几乎任何操作，包括系统命令、文件操作和网络命令等，具有极高的破坏性。  
## 1.Command Injection(Low)  
  
相关代码分析  
```
```  
  
stristr() 函数  
  
搜索字符串在另一字符串中的第一次出现。该函数是二进制安全的, 且是不区分大小写的。如需进行区分大小写的搜索，要使用 strstr() 函数。  
  
php_uname()函数  
  
返回运行 PHP 的系统的有关信息。  
  
'a'：此为默认。包含序列 "s n r v m" 里的所有模式。  
  
's'：操作系统名称。例如： FreeBSD。  
  
'n'：主机名。例如： localhost.example.com。  
  
'r'：版本名称，例如： 5.1.2-RELEASE。  
  
'v'：版本信息。操作系统之间有很大的不同。  
  
'm'：机器类型。例如：i386  
  
可以看到, 服务端代码仅仅根据操作系统的不同, 执行相应的命令, 没有进行任何过滤, 导致了严重的命令执行漏洞。  
  
命令是用分号;分隔的, 所以尝试注入:  
  
;ls /  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4Warq4Gmq5QQAmIVyKRsrW22h0Bcnmxl8mA4TicQiaibnWnw4A6VC9tib9sdoQ/640?wx_fmt=png&from=appmsg "")  
  
还可以用&&来执行, &&当第一个命令执行成功时(返回0), 才执行&&后面的命令  
  
command1 && command2  
  
如果command1执行成功，则执行command2  
  
baidu.com && pwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4War9A9MWG5zibrY7iaawF661xFHcfggGhVtlGgxrmo7jucA8UibhCsl9DAew/640?wx_fmt=png&from=appmsg "")  
  
baidu.com & pwd  
  
baidu.com || pwd  
  
结果相同  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4Warhh0ibWC7EcsLNNFQwIn3VwYMLibYbERZphPzYBPFAWARpKcRGmGFicic7w/640?wx_fmt=png&from=appmsg "")  
  
baidu.com | pwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarhjkQdU3Rkscu0nkl4nP7fF2Qr9xfgb92ORyLwuHaE9PU44TG8tqfrA/640?wx_fmt=png&from=appmsg "")  
## 2.Command Injection(Medium)  
  
相关代码分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarDcvwticC3dNtyHGUskia6qx9Jom5wsjpLGOVzylNYZCtagBWWmCVN4fg/640?wx_fmt=png&from=appmsg "")  
  
服务器端对ip参数做了一定过滤，即把”&&” 、”;”删除，本质上采用的是黑名单机制，因此依旧存在安全问题。  
  
采用黑名单过滤, 可以理解为一种枚举过滤, 列举出可能出现的漏洞, 然后过滤; 但是很多情况下是枚举不完的, 依旧存在漏洞  
  
只有”&&”与” ;”被过滤了，所以”&”不会受影响。  
  
输入baidu.com & pwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarE8yTKo3NfgfmKRibgknwQUHNmyoD423YsUSZOjAeN7baGdTV7hz8ebQ/640?wx_fmt=png&from=appmsg "")  
  
方式：command1 | command2  
  
command1的输出作为command2的输入  
  
baidu.com | pwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarSSCicQMXakicIEqO8JdPcicrU7c1HKcx0hzoQuxoeCpTK49UofEib87mKw/640?wx_fmt=png&from=appmsg "")  
  
方式：command1 || command2  
  
如果command1执行失败，则执行command2  
  
baidu.com || pwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarfHkia0BOwHJpLbBF7CnOOaHLYYLmB1I74g9d8sgckeQTFScbH3UEfLw/640?wx_fmt=png&from=appmsg "")  
## 3.Command Injection(High)  
  
相关代码分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarYfnWwgpPqicPddE32jFMsXrhfyN6IBsUxtFfGia8b8vU8ia0gYcsp6ocQ/640?wx_fmt=png&from=appmsg "")  
  
在High级别中, 将一些主要的命令执行关键字( & ; | ...) 给替换为空了, 但是由于黑名单过滤的局限性, 还是存在漏洞的。  
  
仔细观察发现, 仅仅是把 | (带一个空格) 给替换为空了, 实际上并没有把 | (管道符)给过滤  
  
127.0.0.1|ls  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarhtCvh9oFKdP3UmVOT3yjUFyHETanWVpVza2pRDmtjl8sJAIWm128ibg/640?wx_fmt=png&from=appmsg "")  
## 4.Command Injection(Impossible)  
  
相关代码分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4WarKYyWDt0emB9lkpj02VVNxfMibdIpDic6OsKUzJdjR5eeEibPYQ4Gf2Mdw/640?wx_fmt=png&from=appmsg "")  
  
相关函数介绍  
  
stripslashes(string)  
  
stripslashes函数会删除字符串string中的反斜杠，返回已剥离反斜杠的字符串。  
  
explode(separator,string,limit)  
  
把字符串打散为数组，返回字符串的数组。参数separator规定在哪里分割字符串，参数string是要分割的字符串，可选参数limit规定所返回的数组元素的数目。  
  
is_numeric(string)  
  
检测string是否为数字或数字字符串，如果是返回TRUE，否则返回FALSE。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4Warby9PAxtuaOCoFoNX7KDicpfgf4y2PscrWjcTshC7Ox60PGhOYibUy0hg/640?wx_fmt=png&from=appmsg "")  
  
可以看到，Impossible级别的代码加入了Anti-CSRF token，同时对参数ip进行了严格的限制，只有诸如“数字.数字.数字.数字”的输入才会被接收执行，因此不存在命令注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpz9ibpxzibyL3tibJibZTJl4War19oPN9ZReGT7Wkvn4zejKJib2ib7fuRJpHq2MRoHsate4JEBpuvkFicicw/640?wx_fmt=png&from=appmsg "")  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
```
```  
  
  
