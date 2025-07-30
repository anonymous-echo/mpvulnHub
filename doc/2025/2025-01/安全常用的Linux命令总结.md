#  安全常用的Linux命令总结   
泷羽Sec-后半生  泷羽Sec-后半生   2025-01-09 10:10  
  
# 前言  
  
网络安全常用命令，两万多字Linux常用命令总结，附详细图文  
### 往期推荐  
  
[](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247485366&idx=1&sn=d000689bc42cb4931657c9a081deebb5&scene=21#wechat_redirect)  
[轻松学习shell编程](https://mp.weixin.qq.com/s?__biz=Mzk1NzIzOTc5MQ==&mid=2247483825&idx=1&sn=a072a1dbcebe960a2152abbcfcd2c4bd&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247485366&idx=1&sn=d000689bc42cb4931657c9a081deebb5&scene=21#wechat_redirect)  
[OSCP+你值得拥有的证书](https://mp.weixin.qq.com/s?__biz=Mzk1NzIzOTc5MQ==&mid=2247483711&idx=1&sn=738d386912442b3b8966010cda7e9226&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247485366&idx=1&sn=d000689bc42cb4931657c9a081deebb5&scene=21#wechat_redirect)  
[oscp备考--办理护照详细流程](https://mp.weixin.qq.com/s?__biz=Mzk1NzIzOTc5MQ==&mid=2247483701&idx=1&sn=c0a714e05a229ac46af311dfae3929a5&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247485366&idx=1&sn=d000689bc42cb4931657c9a081deebb5&scene=21#wechat_redirect)  
[KFC全家桶--都没有nuclei全家桶香](https://mp.weixin.qq.com/s?__biz=Mzk1NzIzOTc5MQ==&mid=2247483694&idx=1&sn=9fddf57f6f6b94b2e1974a1c4ed34c84&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247485366&idx=1&sn=d000689bc42cb4931657c9a081deebb5&scene=21#wechat_redirect)  
## openssl  
  
openssl是一个开源的加密工具包，提供了各种加密、解密、签名、验证等功能  
```
```  
  
password表示这个命令用于处理密码相关的操作，-1参数指定使用MD5加密算法对密码“123”进行加密处理。MD5是一种常用的哈希算法，它将任意长度的输入数据转换为固定长度的输出（通常是128位的哈希值）。使用这个命令可以将“123”生成为MD5加密后的密文  
```
```  
  
-5参数表示使用SHA-256哈希算法对密码“123”进行哈希加密处理。SHA-256是一种更安全的哈希算法。它生成的哈希值长度为256位。每次对相同的密码进行SHA-256加密时，由于加密过程中通常会引入随机因素（如盐值等），所以每次生成的密文都是不一样的，这增加了密码的安全性，即使攻击者获得了密文，也很难通过逆向计算得到原始密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IGCCuA7JmVjDfvDqGLAib96EPnWpUXtyK5HNR02VsibUj4slPzZSicERuQ/640?wx_fmt=png&from=appmsg "")  
  
## 文件管理  
### stat  
- 显示文件的详细信息，包括时间戳  
  
```
```  
### touch  
  
主要用于更新文件的访问时间和修改时间（时间戳）。如果指定的文件不存在，  
touch  
 命令会创建一个新的空文件。  
```
```  
  
参数  
```
```  
1. **创建多个新文件**  
:  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IWCEjWo8akxMxpTt9mRMOIu8YKHpHgrdib586azW7X4iaZoaBTGzLCbQA/640?wx_fmt=png&from=appmsg "")  
1. **更新文件的修改时间为特定时间**  
:  
  
```
```  
1. **使用参考文件的时间戳更新目标文件**  
:  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I8X2lNjmltTrUXeEEUEPjmRt1Am2ImQ7xwA8XBWd1lQWWibspgQG7miaw/640?wx_fmt=png&from=appmsg "")  
1. **仅更新文件的访问时间**  
:  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IJDXMCalGCicaXMFWd49kjVfZukTNRcg6NEMOelffPrx2Kp3WnNMiaWkA/640?wx_fmt=png&from=appmsg "")  
1. **仅更新文件的修改时间**  
:  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IiaUSiaUnX87ic1NLO0ZAYBKCjXIibpzKAXWBQoPGAZ8v53x25T3TQibic0XA/640?wx_fmt=png&from=appmsg "")  
1. **使用自然语言描述的日期和时间**  
:  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ItsfbEDs6kgicfXhqLBYEbiaLMEBuvuTHicNwwnSqpqnxJnOwn9vRiaTPBg/640?wx_fmt=png&from=appmsg "")  
### rm  
```
```  
  
   
**删除多个文件**  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I0K7OHevwjmU6fHamLhv5rclfpl73mdjnnahmBSrkQbfzg6wLN1JF2Q/640?wx_fmt=png&from=appmsg "")  
  
  
**删除目录**  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IMDMbK2IlPIHGp268Jlwdb2ogEbb6KkmS0qoaeVMnyyr6V3SbXWF9uQ/640?wx_fmt=png&from=appmsg "")  
### mkdir  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IpO2PvicbUrEwduuRjMcVydUdWYFdh2ibnSFOjXHwaO2cfgCsPtE960Cg/640?wx_fmt=png&from=appmsg "")  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ISHG04M25OZxtnQdHgcHbKCba4IrPwcBJkXH8TLbrB9riaYBibBAiadFjg/640?wx_fmt=png&from=appmsg "")  
  
  
**设置目录权限**  
```
```  
  
创建一个名为   
mydir  
 的目录，并将其权限设置为   
755  
（即所有者有读、写、执行权限，组用户和其他用户有读和执行权限）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IuoWq6qbqmCiaA8YdD4tFtLW2y8u6s3PvJvsGrTWJ7pelKzkNwMsU4icQ/640?wx_fmt=png&from=appmsg "")  
  
### rmdir  
  
与   
rm  
 命令不同，  
rmdir  
 只能删除空目录，不能删除包含文件或子目录的目录  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I9I70icyujtY6lAV0P3K1sAo2vCXne1JdlMW9R32aibP9hsJfjsbuuqxQ/640?wx_fmt=png&from=appmsg "")  
### mv  
  
用于移动文件和目录，也可以用来重命名文件和目录  
```
```  
  
这条命令将当前目录下的   
file1.txt  
 重命名为   
file2.txt  
。如果   
file2.txt  
 已经存在，它会被覆盖  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Iw5gT7TNC30lEgVib88M7NLB0yF9swy62sl1uuGJibhCYhDPCnhE1msBA/640?wx_fmt=png&from=appmsg "")  
  
1. **不覆盖模式移动文件**  
:  
  
```
```  
  
如果   
file2.txt  
 已经存在，不会覆盖，也不会提示。  
1. **强制移动文件**  
:  
  
```
```  
  
即使   
file2.txt  
 已经存在，也会直接覆盖，不会提示确认。  
1. **更新模式移动文件**  
:  
  
```
```  
  
只有当   
file1.txt  
 比   
file2.txt  
 新或   
file2.txt  
 不存在时，才会移动。  
  
**参数**  
  
**-i**  
: 交互模式，如果目标文件或目录已经存在，会提示确认是否覆盖  
  
**-v**  
: 显示详细信息，显示移动或重命名的每个文件或目录  
### cp  
```
```  
  
**参数**  
- -i  
 或   
--interactive  
：在覆盖已存在的文件之前提示用户。  
  
- -r  
,   
-R  
,   
--recursive  
：递归地复制目录及其子目录下的所有文件。如果目标是一个目录，则会将源目录下的所有内容复制到该目录下。  
  
- -u  
,   
--update  
：仅当目标文件比源文件旧，或目标文件不存在时才进行复制。  
  
- -v  
,   
--verbose  
：显示详细的处理信息，比如复制了哪些文件。  
  
- -a  
,   
--archive  
：归档模式，等同于   
-dR --preserve=all  
，用于保持原始文件的所有属性（如权限、时间戳等）。  
  
- -f  
,   
--force  
：如果目标文件无法打开或写入，则删除它并尝试再次复制。  
  
- -p  
：保留源文件或目录的属性（如修改时间、访问时间和权限）。  
  
1. **复制多个文件到一个目录**  
：  
  
```
```  
  
这里，  
file1.txt  
 和   
file2.txt  
 都会被复制到   
/path/to/destination/  
 目录下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IQFs3dYic4eY8dlNmjKkdm21K4ibWnCeduicdetcDbgnFxaylQqwqaPuMA/640?wx_fmt=png&from=appmsg "")  
  
1. **递归复制目录**  
：  
  
```
```  
  
这个命令将   
directory/  
 及其所有内容复制到新的   
newdirectory/  
 中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Inla3pku1zLd03AoIqCjYD0TxeImia6Vxm88Fcvwy386dcwFeibCZvW3A/640?wx_fmt=png&from=appmsg "")  
  
1. **更新模式复制**  
：  
  
```
```  
  
只有当   
source.txt  
 比   
destination.txt  
 新或   
destination.txt  
 不存在时，才会执行复制操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I0Ly6I5Lj9vv6kmEwYuQiajaTibtIMEjBLFOcdk6Aib4ANBkAc7Rsc7tOQ/640?wx_fmt=png&from=appmsg "")  
  
### ln  
  
链接分为两种类型：硬链接（hard link）和符号链接（symbolic link，也称软链接）。下面详细介绍   
ln  
 命令的用法和选项。  
#### 基本语法  
```
```  
#### 参数  
- -s  
,   
--symbolic  
：创建符号链接（软链接）而不是硬链接。  
  
- -f  
,   
--force  
：如果目标文件已经存在，则删除目标文件后创建链接。  
  
- -i  
,   
--interactive  
：在覆盖已存在的文件之前提示用户。  
  
- -v  
,   
--verbose  
：显示详细的处理信息。  
  
- -n  
,   
--no-dereference  
：当目标是一个符号链接时，不会跟随符号链接的目标，而是直接替换符号链接本身。  
  
**链接类型**  
1. **硬链接**  
：  
  
1. 硬链接是指向同一个 inode（索引节点）的多个文件名。每个硬链接都是一个独立的文件名，但它们共享相同的数据。  
  
1. 硬链接不能跨文件系统创建，也不能指向目录。  
  
1. **符号链接（软链接）**  
：  
  
-软连接是一个特殊的文件，它包含了一个路径，指向另一个文件或目录。  
  
-软连接可以跨文件系统创建，并且可以指向目录。  
  
#### 软连接  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I3Mg3yicw7Q5fOKl4tJTdUO6D1feV895LjYpp1HxNTFBsZVH2jvnHleQ/640?wx_fmt=png&from=appmsg "")  
  
**注意事项**  
- 软连接可以跨文件系统创建。  
  
- 软连接可以指向目录。  
  
- 删除源文件会使符号链接失效（成为“断链”）。  
  
#### 硬链接  
```
```  
  
~/offsec123.txt  
：源文件的路径。  
~  
 表示当前用户的主目录。  
hardlink.txt  
：创建的硬链接的名称。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Ix4y2KukgAoRlZTswWQfGymwJTMicgbeNM4eo4VoRQX8EwcFA2EXfib0A/640?wx_fmt=png&from=appmsg "")  
  
  
**主要事项**  
- 硬链接不能跨文件系统创建。  
  
- 硬链接不能指向目录。  
  
- 删除源文件不会影响硬链接，因为它们共享同一个 inode。  
  
#### 示例  
1. **创建硬链接**  
：  
  
```
```  
  
这条命令将在当前目录下创建一个名为   
hardlink.txt  
 的硬链接，指向   
file.txt  
。  
1. **创建符号链接**  
：  
  
```
```  
  
这条命令将在当前目录下创建一个名为   
symlink.txt  
 的符号链接，指向   
/path/to/file.txt  
。  
1. **强制创建符号链接**  
：  
  
```
```  
  
如果   
existing_symlink.txt  
 已经存在，这条命令会先删除它，然后创建一个新的符号链接。  
1. **在目录中创建多个链接**  
：  
  
```
```  
  
这条命令将在   
/path/to/directory/  
 目录下创建   
file1.txt  
 和   
file2.txt  
 的硬链接。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IpvDCE88ZQ44zeeJCK12SG9OmBTqIWOpLptBwqIkltpQM3ib7kVBatAw/640?wx_fmt=png&from=appmsg "")  
  
1. **创建指向目录的符号链接**  
：  
  
```
```  
- 连接文件夹需要自己创建  
  
这条命令将在   
/path/to/link_directory  
 创建一个符号链接，指向   
/path/to/source_directory  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IaL6x2jpKtYraGiakhh8pxH3Ymm1MUGU6pZ2oCbUXHicJfkrQDL6n3mIw/640?wx_fmt=png&from=appmsg "")  
  
  
### 文件读取  
#### cat  
  
首先是最常见的，那就是cat了，用于连接文件并打印到标准输出设备上，用法为：  
```
```  
  
不需要完整文件名    
#### tac  
  
用于将文件以行为单位的反序输出，用法为：  
```
```  
  
不需要完整文件名    
#### more/bzmore  
  
类似cat命令，会以一页一页的显示，方便使用者逐页阅读，用法为  
```
```  
  
不需要完整文件名    
#### less/bzless  
  
作用与more类似,都用来浏览文本文件中的内容,不同之处在于,使用 more 命令浏览文件内容时,只能不断向后翻看,而使用 less 命令浏览,既可以向后翻看,也可以向前看。用法为：  
```
```  
  
不需要完整文件名    
#### head  
  
head 命令可用于查看文件的开头部分的内容，有一个常用的参数 -n 用于显示行数，默认为 10，即显示 10 行的内容。用法为：  
```
```  
  
不需要完整文件名    
#### tail  
  
作用和head相似，但它默认显示最后 10 行。用法为：  
```
```  
  
不需要完整文件名    
#### nl  
  
可以为输出列加上编号。用法为：  
```
```  
  
不需要完整文件名    
#### sed  
  
Sed 代表流编辑器Stream Editor，常用于 Linux 中基本的文本处理.用法为：  
```
```  
  
不需要完整文件名    
#### sort  
  
用于将文本文件内容加以排序。用法为：  
```
```  
  
不需要完整文件名    
#### uniq  
  
删除文件中的连续重复行 如果你在不使用任何参数的情况下使用 uniq 命令,它将删除所有连续的重复行,只显示唯一的行。用法为：  
```
```  
  
不需要完整文件名    
#### rev  
  
反转一个或多个文件的行。用法为  
```
```  
  
不需要完整文件名，获得的是逆序的flag  
    
  
当然，我们可以使用rev /f* | rev获得正序的flag:    
#### od  
  
od(Octal Dump)命令用于将指定文件内容以八进制、十进制、十六进制、浮点格式或 ASCII 编码字符方式显示,系统默认的显示方式是八进制。用法为：  
```
```  
  
不需要完整文件名  
    
  
你可能会奇怪中间那个0000020是啥，我们可以看到这个命令在linux里的运行结果：  
    
  
左边一列其实是它的地址，记得把地址0000020删了就是文件内容了，当然直接f12也可以看到linux里那样的运行结果：    
#### vim/vi  
  
这俩都是Linux里的文件编辑器，我们在网页直接用system("vim /f*");虽然不会进入编辑模式但还是可以看到里面的内容。用法为:  
```
```  
  
不需要完整文件名    
#### man  
  
man 命令是 Linux 下的帮助指令，通过 man 指令可以查看 Linux 中的指令帮助、配置文件帮助和编程帮助等信息，类似于vim/vi，直接对文本运行可以看到文本内容。用法为：  
```
```  
  
不需要完整文件名    
#### paste  
  
使用paste命令可以将每个指定文件里的每一行整合到对应一行里写到标准输出,之间用制表符分隔。用法为：  
```
```  
  
不需要完整文件名    
#### grep  
  
查找文件里符合条件的字符串。用法为：  
```
```  
  
不需要完整文件名    
#### file  
  
查看文件信息或类型。用法为：  
```
```  
  
不需要完整文件名    
#### dd  
  
用于读取、转换并输出数据。用法为：  
```
```  
  
需要完整文件名    
#### date  
  
使用指定格式显示时间，或者设置系统时间，有时用于suid提权。用法为：  
```
```  
  
不需要完整文件名。但他本质上是一种报错读取，直接system传值是没回显的，我们要读取报错才行：  
```
```  
  
然后再编一下码：  
```
```  
#### 报错读取  
  
linux里可以用点号执行shell脚本，同样，我们也可以用这种方法报错读取文件内容，前提是你的用户组有  
**读取文件的权限**  
```
```  
  
如果你的用户组有  
**执行文件的权限**  
，你可以直接/f*获得文件内容：  
```
```  
#### diff  
  
用于比较文件的内容，我们可以把想读取的文件内容和一个已知的文件进行比较，获得差集也就是我们想要的内容了，如：  
```
```  
  
不需要完整文件名    
## 搜索文件  
### which  
  
which  
 命令是Linux系统中用于查找并显示给定命令的绝对路径的一个工具。它通过检查环境变量   
PATH  
 中列出的目录来确定可执行文件的位置。这对于了解某个命令是否已安装以及其具体位置非常有用。下面是关于   
which  
 命令的一些重要细节：  
#### 基本语法  
```
```  
#### 参数  
- -a  
：显示所有匹配的可执行文件路径。默认情况下，  
which  
 只显示第一个匹配项。  
  
- --skip-alias  
：跳过别名，直接显示实际命令的路径。  
  
- -V  
 或   
--version  
：显示   
which  
 命令的版本信息。  
  
#### 使用示例  
1. **查找单个命令的位置**  
  
```
```  
  
这条命令将返回   
java  
 命令的完整路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IL7vQsnAibHXjCvP7ELrDJV7siaIPcjgr4Kkco6DsbEH19MdKdZYxFTTw/640?wx_fmt=png&from=appmsg "")  
  
  
如果使用which命令返回，证明可能文件有同名加上-a参数即可  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IhMBPNJDsfChCyd066XjZh8KmlMSJdhzVa4aZpicB0tnzwxcRUrbqlRQ/640?wx_fmt=png&from=appmsg "")  
1. **查找多个命令的位置**  
  
```
```  
  
这条命令会分别显示   
man  
,   
java  
, 和   
python  
 命令的路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IsWTDBcu4ziaBbyb6iaYKVTVOs0ciaIoiaQvmUgGgia7ZdZ2Fvz2vhO2NSlQ/640?wx_fmt=png&from=appmsg "")  
  
1. **显示所有匹配的路径**  
  
如果一个命令在多个路径中有副本，可以使用   
-a  
 选项来显示所有副本的位置。  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I42H9uI522Z6fDv3pAWOuMT3RpZXMBRTJ4t5zsgqiceMydkt9q2iciaeLQ/640?wx_fmt=png&from=appmsg "")  
1. **查找别名的位置**  
  
如果你为某个命令设置了别名，  
which  
 会显示别名的定义。  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Iibke6IWkDvDHHoRicFkOESVn6HeyahThs6fYcaIuDFgZIJPj6roia8icPQ/640?wx_fmt=png&from=appmsg "")  
1. **查找并忽略别名**  
  
使用   
--skip-alias  
 选项可以跳过别名，直接获取命令的实际路径。  
  
```
```  
  
如果不能使用，可以先  
```
```  
1. **查看 which 自身的位置**  
```
```  
  
这条命令显示   
which  
 命令本身的路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IpPgwJokhgWjUyD5c8akTAOaLbCmkBFsLaiciaLNabq1mrqCD2xojf5Xw/640?wx_fmt=png&from=appmsg "")  
  
  
#### 注意事项  
- which  
 命令只能用于查找可执行文件，对于其他类型的文件（如文档或源代码文件），应该使用   
whereis  
 或   
find  
 命令。  
  
- 如果   
which  
 没有找到指定的命令，那么它将不会有任何输出，这表示该命令不在   
PATH  
 环境变量指定的任何目录中。  
  
- which  
 的搜索结果受到   
PATH  
 环境变量的影响，不同的用户可能会有不同的   
PATH  
 设置，因此即使是相同的命令，在不同的用户环境下也可能得到不同的搜索结果。  
  
通过这些基本信息，你应该能够有效地使用   
which  
 命令来查找Linux系统中命令的具体位置。  
### locate (local.db)  
  
locate  
 命令是 Linux 系统中用于快速查找文件和目录的工具。它通过搜索预先构建的数据库来查找文件，而不是实时搜索文件系统。这使得   
locate  
 命令比   
find  
 命令更快，但前提是数据库必须是最新的。  
#### 基本语法  
```
```  
#### 选项  
  
wh  
- -b  
：仅匹配基础文件名（即不包括路径）。  
  
- -c  
：仅显示找到的文件数量。  
  
- -i  
：忽略大小写。  
  
- -n <数目>  
：最多显示指定数量的匹配项。  
  
- -P  
 或   
--no-check-existing  
：不检查文件是否存在。  
  
- -r  
：使用正则表达式进行匹配。  
  
- -S  
：显示数据库统计信息。  
  
- -u  
：更新数据库（通常由   
updatedb  
 命令完成）。  
  
- -0  
：以空字符分隔结果，适合用于脚本处理。  
  
#### 使用示例  
1. **基本使用**  
  
```
```  
  
查找whoami.exe的位置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IicUUWNvooHXh4u3XZosrGovSO2nic9300HETAdbS64Qq4TayqViaejhZg/640?wx_fmt=png&from=appmsg "")  
  
1. **忽略大小写**  
  
```
```  
  
   这条命令会查找包含   
Whoami.exe  
 的文件，忽略大小写。  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6It71ibA0F0TAnfeVNC7FEiaqk1gJ8GujWKhuGRdUjgkIhZreJMVEhZibKQ/640?wx_fmt=png&from=appmsg "")  
  
1. **限制结果数量**  
  
```
```  
  
   这条命令最多显示 5 个匹配项。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6InfnylUVmPpW54sCnKoIMfURa5LjBUjXM0umyLedUyJH3yVtPIp5jng/640?wx_fmt=png&from=appmsg "")  
  
1. **使用正则表达式**  
  
```
```  
  
   这条命令会查找   
/home  
 目录下所有以   
.txt  
 结尾的文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IBlcN8qSPl8nM7fibAm1IXRicqKflV7fTEhianWWvP9c3GiaicI2bykdnibSA/640?wx_fmt=png&from=appmsg "")  
  
1. **仅匹配基础文件名**  
  
```
```  
  
   这条命令会查找基础文件名为   
user  
 的文件，不包括路径。  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IItHhRLOjicVE6lbV9SGca92xnnIcOQFwTQUTvA9lDY9Dx9VPqDujCBw/640?wx_fmt=png&from=appmsg "")  
  
1. **显示找到的文件数量**  
  
```
```  
  
   这条命令会显示找到的   
ls  
 文件的数量。  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IRibTCoE00YtRUn5y0QK2YicWleSFaicYvrA7tdibvEomTmljaj9D3x8s3A/640?wx_fmt=png&from=appmsg "")  
  
#### 更新数据库  
  
locate  
 命令依赖于一个预先构建的数据库，该数据库通常由   
updatedb  
 命令定期更新。你可以手动运行   
updatedb  
 来更新数据库。  
```
```  
#### 注意事项  
- **数据库更新**  
：  
locate  
 命令的速度优势来自于预构建的数据库。如果文件系统发生了变化，而数据库没有及时更新，  
locate  
 的结果可能不准确。因此，建议定期运行   
updatedb  
。  
  
- **权限问题**  
：  
updatedb  
 通常需要 root 权限来访问所有目录和文件。  
  
- **性能**  
：虽然   
locate  
 很快，但如果文件系统非常大，  
updatedb  
 的运行时间可能会较长。  
  
### find  
  
find  
 命令是 Linux 系统中一个非常强大且灵活的文件查找工具。它可以基于多种条件（如文件名、文件类型、修改时间、文件大小等）来查找文件和目录。下面是对   
find  
 命令的详细解释，包括其基本语法、常用选项和一些实用示例。  
#### 基本语法  
```
```  
#### 文件名和路径  
- -name <pattern>  
：按文件名查找，支持通配符   
*  
、  
?  
 和   
[ ]  
。  
  
- -iname <pattern>  
：按文件名查找，忽略大小写。  
  
- -path <pattern>  
：按路径查找，支持通配符。  
  
- -ipath <pattern>  
：按路径查找，忽略大小写。  
  
- -user 用户  :选项指定要查找的文件必须属于指定用户  
  
#### 文件类型  
- -type <type>  
：按文件类型查找。  
  
- f  
：普通文件  
  
- d  
：目录  
  
- l  
：符号链接  
  
- c  
：字符设备  
  
- b  
：块设备  
  
- p  
：命名管道（FIFO）  
  
- s  
：套接字  
  
#### 文件大小  
- -size <size>  
：按文件大小查找。  
  
- +n  
：大于 n 字节  
  
- -n  
：小于 n 字节  
  
- n  
：恰好 n 字节  
  
- nK  
：n 千字节  
  
- nM  
：n 兆字节  
  
- nG  
：n 吉字节  
  
#### 修改时间  
```
```  
- -mtime <n>  
：按文件修改时间查找。  
  
- +n  
：n 天前修改过的文件  
  
- -n  
：n 天内修改过的文件  
  
- n  
：恰好 n 天前修改过的文件  
  
- -atime <n>  
：按文件访问时间查找。  
  
- -ctime <n>  
：按文件状态改变时间查找。  
  
#### 执行操作  
- -exec <command> {} \;  
：对找到的每个文件执行命令。  
  
- -ok <command> {} \;  
：类似   
-exec  
，但会提示用户确认。  
  
- -delete  
：删除找到的文件。  
  
#### 实用示例  
1. **按文件名查找**  
  
```
```  
  
   这条命令会在家目录及其子目录中查找以flag开头的文件  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IdXja7qKz3XOvdSDJNwicZeWPR3wcOB29IjNWze3Av7z4fZWsJBt4o9Q/640?wx_fmt=png&from=appmsg "")  
  
1. **忽略大小写查找**  
  
```
```  
  
  这条命令会在家目录及其子目录中查找以flag开头的文件，且忽略大小写  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I6rd8dfZhdGAMbgOzTmXsrHwTIiaNzDibZMxdDr9zBCRCFy0EMyQnJLzw/640?wx_fmt=png&from=appmsg "")  
  
1. **按路径查找**  
  
```
```  
  
   这条命令会在家目录及其子目录中查找路径中包含   
logs  
 且文件名以   
.log  
 结尾的文件。  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IRzoByxgeIKicR6tFjjhCQib8ZkfIe4nPiaYicd21xribicA8ticRBln4mAG5w/640?wx_fmt=png&from=appmsg "")  
  
1. **按文件类型查找**  
  
```
```  
  
   这条命令会在当前目录及其子目录中查找所有的目录  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Iod5u6C8icAvPBibEM6LHaZiaCqLdQYmIrSAEEibLyOoZCta2viaEiaQ6Wxng/640?wx_fmt=png&from=appmsg "")  
  
1. **按文件大小查找**  
  
```
```  
  
   这条命令会在家目录及其子目录中查找大于 100MB 的文件。  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IYopGGAL555kdxtQBwdYpmLacZcgv4htFZjfWeGmlybIXibCtgKYc9TQ/640?wx_fmt=png&from=appmsg "")  
  
1. **按修改时间查找**  
  
```
```  
  
查找家目录及其子目录中在过去 30 分钟内被修改过的所有文件和目录。  
  
     
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IoqiaAUWKD04oDibr7u35hibjVtMIqg9HxMzhUmMmMiaM2jq7ODDmxKworw/640?wx_fmt=png&from=appmsg "")  
  
1. **执行命令**  
  
```
```  
- **~**  
：指定要搜索的目录路径为家目录。  
  
- **-name "*.txt"**  
：按文件名查找，匹配所有扩展名为   
.txt  
 的文件。  
  
- *  
：通配符，匹配任意字符序列。  
  
- *.txt  
：匹配所有以   
.txt  
 结尾的文件。  
  
- **-exec cat {} \;**  
：对找到的每个文件执行   
cat  
 命令。  
  
- {}  
：占位符，表示当前找到的文件路径。  
  
- \;  
：表示   
-exec  
 命令的结束。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IduYAgalbMw4FHto3QlsdJGzYTIdhnsfV75dmHa8PXkcIZ83tyMQMtw/640?wx_fmt=png&from=appmsg "")  
  
  
1. **删除文件**  
  
```
```  
  
在当前目录及其子目录中查找所有   
.txt  
 文件并删除它们。  
#### 组合使用  
```
```  
1. **find ~ -mtime 2 -ls**  
：  
  
1. ~  
：表示当前用户的家目录。  
  
1. -mtime 2  
：查找恰好在 2 天前被修改的文件。  
  
1. -ls  
：显示找到的文件的详细信息，输出格式类似于   
ls -l  
，包括文件权限、链接数、所有者、组、文件大小、修改日期和时间、文件路径等。  
  
1. **sort -k9 -k10**  
：  
  
1. sort  
：对输入进行排序。  
  
1. -k9  
：按第 9 列排序，一般是日期的那一列  
  
1. -k10  
：按第 10 列排序，一般是时间的那一列  
  
1. 这两个选项结合起来可以按文件名进行排序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IP4MPRE2OD9epL8Enib3gBPIpialyJicwBIL4xYjTz8CORmRrSSaxtWibwQ/640?wx_fmt=png&from=appmsg "")  
  
  
1. **more**  
：  
  
1. more  
：分页显示输出，方便查看大量输出内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IE6lzgElTvQhy7t30yGJpzLzmZDtkIshTdkx7QF02oSy6pMkaWCQ7Bw/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
1. **-type f**  
：  
  
1. 查找普通文件（不包括目录、符号链接等）。  
  
1. **-iname '*.sh'**  
：  
  
1. 按文件名查找，支持通配符   
*  
，并且不区分大小写。  
  
1. *.sh  
：匹配所有以   
.sh  
 结尾的文件。  
  
1. -iname  
：不区分大小写。  
  
1. **-mmin -30**  
：  
  
1. 按分钟数查找文件的最后修改时间。  
  
1. -30  
：表示在过去 30 分钟内被修改的文件。  
  
1. **-ls**  
：  
  
1. 显示找到的文件的详细信息，类似于   
ls -l  
 命令的输出，包括文件权限、链接数、所有者、组、文件大小、修改日期和时间、文件路径等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I9Qdk1807h3uGptibN5CsVichK3WZx6gAVIyyITiccaPWicTDdgX5xTVVEA/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
1. **find .**  
：  
  
1. 从当前目录（  
.  
）开始搜索。  
  
1. **-name '.svn'**  
：  
  
1. 查找所有名为   
.svn  
 的目录。  
  
1. **-exec rm -rf {} \;**  
：  
  
1. 对每个找到的   
.svn  
 目录执行   
rm -rf  
 命令，递归删除这些目录及其内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I7icVa0f2Rk4HExX6C6GGPYP5JTDJLX77YczDdBh6ibiashRWhA35tFMVQ/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
  
**-user kali**  
:  
  
    - 这个选项指定要查找的文件必须属于用户   
kali  
。只有那些所有者为   
kali  
 的文件才会被选中。  
  
**-type f**  
:  
  
    - 这个选项指定要查找的文件类型为普通文件（即不是目录、符号链接等）。只有普通文件会被考虑。  
  
**-perm -o=w**  
:  
  
    - 这个选项指定要查找的文件必须具有其他用户（  
other  
）的写权限。  
  
    -   
-o=w  
 表示文件至少具有其他用户的写权限，可能还包含其他权限。  
  
    - 具体来说，  
-o=w  
 查找的是权限位中   
others  
 部分包含   
w  
（写权限）的文件。  
  
**-name '*.sh'**  
:  
  
    - 这个选项指定要查找的文件名必须以   
.sh  
 结尾。这通常表示这些文件是 shell 脚本。  
  
**2>/dev/null**  
:  
  
    - 这是一个重定向操作，将标准错误输出（文件描述符 2）重定向到   
/dev/null  
。  
  
    -   
/dev/null  
 是一个特殊的文件，任何写入它的内容都会被丢弃。这样做的目的是忽略   
find  
 命令执行过程中产生的任何错误信息，例如由于权限不足而无法访问某些目录时产生的“Permission denied”消息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Ikd8xnynKVtEZJhMLicgwT2zUJx6VHoXicibiauicBVFvvic3uWogUdQicRdFQ/640?wx_fmt=png&from=appmsg "")  
  
#### 注意事项  
- **性能**  
：  
find  
 命令会实时搜索文件系统，因此在大型文件系统中可能会比较慢。  
  
- **权限**  
：  
find  
 命令可能无法访问某些受权限保护的目录或文件，可以使用   
sudo  
 提升权限。  
  
- **递归**  
：  
find  
 默认会递归搜索子目录，可以在路径后加上   
-maxdepth 1  
 限制搜索深度。  
  
## 账号相关  
### 用户账号数据库相关文件  
```
```  
  
/etc/passwd:  
```
```  
  
**字段解释**  
- **username**  
: 用户名。  
  
- **password**  
: 用户的密码。在现代系统中，这个字段通常包含一个占位符（如   
x  
 或   
*  
），实际的密码信息存储在   
/etc/shadow  
 文件中。  
  
- **UID**  
: 用户的唯一标识符（User ID）。  
  
- **GID**  
: 用户的主要组的唯一标识符（Group ID）。  
  
- **GECOS**  
: 用户的全名或其他注释信息，通常包含用户的全名、办公室位置、电话号码等。  
  
- **home_directory**  
: 用户的家目录路径。  
  
- **shell**  
: 用户的登录 shell。  
  
**示例**  
  
```
```  
  
解释：  
- **root**  
: 用户名。  
  
- **x**  
: 密码字段，表示密码存储在   
/etc/shadow  
 文件中。  
  
- **0**  
: 用户的 UID。  
  
- **0**  
: 用户的主要 GID。  
  
- **root**  
: GECOS 字段，通常包含用户的全名或其他注释信息。  
  
- **/root**  
: 用户的家目录路径。  
  
- **/bin/bash**  
: 用户的登录 shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ItC4nzpztdEd0ianDQf2N4IibUiaeQfGeBzr7zgoaibxcbgmHKibg9DIdFUw/640?wx_fmt=png&from=appmsg "")  
  
  
/etc/shadow:  
  
这个文件也与用户账号相关，主要存储用户密码的加密信息以及密码的一些属性，如密码最后一次修改时间、密码最短使用期限、密码最长使用期限等。  
  
只有具有足够权限的用户（通常是root)才能读取这个文件，以提高密码的安全性。  
  
每行代表一个用户，格式如下：  
  
```
```  
  
**字段解释**  
- **username**  
: 用户名。  
  
- **password**  
: 加密后的密码。如果为空，表示没有设置密码；如果包含   
!  
 或   
*  
，表示账户被锁定。  
  
- **last_changed**  
: 密码上次更改的日期，以 Julian 日期表示（从 1970 年 1 月 1 日算起的天数）。  
  
- **min_age**  
: 密码最短使用期限（天数），在这段时间内用户不能更改密码。  
  
- **max_age**  
: 密码最长使用期限（天数），超过这段时间后用户必须更改密码。  
  
- **warn_inactive**  
: 密码过期前多少天开始警告用户。  
  
- **expire_date**  
: 账户过期日期，以 Julian 日期表示。  
  
- **reserved_field**  
: 保留字段，目前未使用。  
  
**示例**  
  
```
```  
  
解释：  
- **alice**  
: 用户名。  
  
- **$6$hashvalue$anotherhashvalue**  
: 加密后的密码（使用 SHA-512 算法）。  
  
- **18999**  
: 密码上次更改的 Julian 日期。  
  
- **0**  
: 密码最短使用期限为 0 天。  
  
- **99999**  
: 密码最长使用期限为 99999 天。  
  
- **7**  
: 密码过期前 7 天开始警告用户。  
  
- **:::**  
: 保留字段，目前未使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Is2BmWVjnNPDvlS4CGoXcZeEg58d5dC2eU0f4zINMzZZrD3zPU11o2g/640?wx_fmt=png&from=appmsg "")  
  
  
/etc/gshadow  
  
/etc/gshadow  
 文件用于存储用户组的密码和其他安全相关信息。它也是一个只读文件，通常只有 root 用户可以读取和写入。  
  
```
```  
  
**字段解释**  
- **group_name**  
: 用户组的名称。  
  
- **password**  
: 用户组的密码。通常为空或包含   
!  
，表示没有设置密码。  
  
- **admin_list**  
: 用户组的管理员列表，用逗号分隔。  
  
- **member_list**  
: 用户组的成员列表，用逗号分隔。  
  
**示例**  
  
```
```  
  
解释：  
- **root**  
: 用户组名。  
  
- **!**  
: 没有设置密码。  
  
- **::**  
: 管理员列表为空。  
  
- **alice,bob**  
: 成员列表，包含   
alice  
 和   
bob  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IBwBl9CbC0ef4NBsCddfn7ehqibHBYCcjNWiaktZaN38icOVDpBtbJxvibA/640?wx_fmt=png&from=appmsg "")  
  
  
### 组账号相关命令  
```
```  
  
用于显示系统中的用户组信息。  
/etc/group  
 文件包含了系统中所有用户组的定义  
  
每个用户组一行，每一行的格式如下：  
```
```  
- **group_name**  
: 用户组的名称。  
  
- **password**  
: 用户组的密码（在现代系统中，这个字段通常为空或包含   
x  
，表示密码存储在   
/etc/gshadow  
 文件中）。  
  
- **GID**  
: 用户组的标识号（Group ID）。  
  
- **user_list**  
: 属于该用户组的用户列表，用逗号分隔。  
  
**示例输出**  
  
假设   
/etc/group  
 文件的内容如下：  
  
```
```  
  
解释：  
- **root**  
: 用户组名为   
root  
，密码字段为   
x  
（表示密码存储在   
/etc/gshadow  
 中），GID 为   
0  
，成员包括   
alice  
 和   
bob  
。  
  
- **users**  
: 用户组名为   
users  
，密码字段为   
x  
，GID 为   
100  
，成员包括   
alice  
、  
bob  
 和   
carol  
。  
  
- **sudo**  
: 用户组名为   
sudo  
，密码字段为   
x  
，GID 为   
27  
，成员包括   
alice  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ITZ8nsEXv0GLJ46atDov5OrbNEaljpCS04ehnGmAmPZNqIIibwowicyUA/640?wx_fmt=png&from=appmsg "")  
  
  
### /etc/passwd、/etc/shadow、/etc/group之间的关系  
  
它们之间的关系可以这样理解，即先在 /etc/group 文件中查询用户组的 GID 和组名；然后在 /etc/passwd 文件中查找该 GID 是哪个用户的初始组，同时提取这个用户的用户名和 UID；最后通过 UID 到 /etc/shadow 文件中提取和这个用户相匹配的密码。  
### 禁用账号相关命令  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IcRFicuNLPL5IpTGxse0VxhDkDUvZJz2XF6Vs8xNZibGzrUiaonic8wODibw/640?wx_fmt=png&from=appmsg "")  
## 文件系统权限相关  
  
linux系统中一切都是文件  
  
查看权限  
```
```  
  
更改文件所有者  
```
```  
  
修改文件权限  
```
```  
### 一、Linux系统中一切都是文件  
  
在Lⅰux系统中，几乎所有的资源都被抽象为文件，包括硬件设备（如硬盘、网卡等）、进程间通信、网络连接等。这种设计理念使得对各种资源的管理可以通过统一的文件操作方式来进行，大大简化了系统的架构和管理。  
### 二、查看权限  
```
```  
- ls  
: 列出文件或目录的信息。  
  
- -l  
: 使用长格式列出信息，即为每个文件（或目录）提供详细的权限、链接数、所有者、组、大小和修改日期等信息。  
  
- -a  
: 显示所有文件，包括以点（  
.  
）开头的隐藏文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I5gX3KreBic5ibjvJFTRauuJDB6E9NiaY6aEVCNN4QzoBNAFpLDJcCUJqg/640?wx_fmt=png&from=appmsg "")  
  
  
这个输出表示：  
- -rw-r--r--  
: 这部分表示文件的权限设置。具体来说：  
  
- rw-  
 表示文件所有者（  
root  
）具有读取和写入权限。  
  
- r--  
 表示文件所属组（  
root  
）具有只读权限。  
  
- r--  
 表示其他用户也具有只读权限。  
  
- 第一个字符   
-  
 表示这是一个普通文件（如果这里是   
d  
，则表示是一个目录）。  
  
- 接下来的9个字符分为三组，每组3个字符，分别表示文件所有者、文件所属组和其他用户对文件的访问权限。  
  
- 1  
: 这表示文件的硬链接数。硬链接是指向同一文件的不同文件名。这里的1表示没有其他文件名指向这个文件。  
  
- root  
: 这是文件的所有者，即拥有该文件的用户。在这个例子中，文件的所有者是   
root  
。  
  
- root  
: 这是文件所属的组。在这个例子中，文件所属的组也是   
root  
。  
  
- 3171  
: 这是文件的大小，以字节为单位。这里表示   
/etc/passwd  
 文件的大小为 3171 字节。  
  
- 2024年 4月15日  
: 这是文件的最后修改日期。这里表示文件最后一次被修改是在2024年的4月15日。  
  
- /etc/passwd  
: 这是文件的完整路径。  
/etc/passwd  
 是一个重要的系统文件，用于存储用户账户的基本信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Ib7Qb0VBbunmr73W3MrQXoB8bHywlK7qLvuJsXI5n4n03SMj9c0bficw/640?wx_fmt=png&from=appmsg "")  
  
  
- drwxr-xr-x  
: 这部分表示目录的权限设置。具体来说：  
  
- rwx  
 表示文件所有者（  
kali  
）具有读取、写入和执行权限。  
  
- r-x  
 表示文件所属组（  
kali  
）具有读取和执行权限。  
  
- r-x  
 表示其他用户也具有读取和执行权限。  
  
- 第一个字符   
d  
 表示这是一个目录（如果这里是   
-  
，则表示是一个普通文件）。  
  
- 接下来的9个字符分为三组，每组3个字符，分别表示文件所有者、文件所属组和其他用户对目录的访问权限。  
  
- 2  
: 这表示目录的硬链接数。硬链接是指向同一文件的不同文件名。对于目录，这个数字通常表示该目录下的子目录数量加上2（因为每个目录都包含两个特殊条目：  
.  
 和   
..  
）。这里的2表示该目录下只有一个子目录或文件。  
  
- kali  
: 这是目录的所有者，即拥有该目录的用户。在这个例子中，目录的所有者是   
kali  
。  
  
- kali  
: 这是目录所属的组。在这个例子中，目录所属的组也是   
kali  
。  
  
- 4096  
: 这是目录的大小，以字节为单位。这里表示该目录占用的磁盘空间为 4096 字节。实际上，目录的大小通常是一个固定值，因为它主要用于存储目录项的元数据。  
  
- 11月 6日 23:22  
: 这是目录的最后修改日期和时间。这里表示目录最后一次被修改是在11月6日的23:22。  
  
- .  
: 这表示当前目录。在   
ls -la  
 命令的输出中，  
.  
 代表当前目录，而   
..  
 代表父目录。  
  
### 三、更改文件所有者，chown  
  
用于更改文件或目录的所有者和所属组  
```
```  
  
**选项**  
- -c  
 或   
--changes  
：显示更改的文件名。  
  
- -f  
 或   
--silent  
 或   
--quiet  
：忽略错误信息。  
  
- -v  
 或   
--verbose  
：显示处理的文件名。  
  
- -R  
 或   
--recursive  
：递归地处理目录及其子目录中的文件。  
  
- --dereference  
：影响符号链接指向的目标文件，而不是符号链接本身。  
  
- --no-dereference  
：仅更改符号链接的属性，而不是其目标文件的属性。  
  
- --from=当前所有者:当前组  
：仅当文件的所有者和组匹配指定的当前所有者和组时才进行更改。  
  
**更改用户**  
  
```
```  
- chown是改变文件所有者的命令。  
  
- root是新的所有者用户名，☒里表示将文件的所有者改为“root”用户。  
  
- fiIe是要更改所有者的文件名称。执行这个命令后，文件的所有者将变为“root”用户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IUboya3bQONkV2lVtH4yOTDxgCMVFIqClfa2cyzLD2gjzcfg1nuGKMg/640?wx_fmt=png&from=appmsg "")  
  
  
**更改文件所属组**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IicrkLO8le3xgqdyfB9B80hKIkqJPHQ9MYtOJ6Sial493HdmkXV1TqTLg/640?wx_fmt=png&from=appmsg "")  
  
  
**同时更改文件所有者和所属组**  
：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IymdtEicEIDTlpMDqCZnYAPYNMTIL3aSx6PHn7eiauGLrOebVmtrMaibibw/640?wx_fmt=png&from=appmsg "")  
  
**递归更改**  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IXESMicUXFSwmYKfaXKoIbUQXDYIbEAmGwKpb8I4jSC212GibC87Q7KZg/640?wx_fmt=png&from=appmsg "")  
### 四、修改文件权限，chmod  
  
chmod  
 命令在 Linux 和类 Unix 操作系统中用于更改文件或目录的权限。权限可以分为三类：用户（所有者）、组和其他用户（其他人）。每类权限又可以细分为读（  
r  
）、写（  
w  
）和执行（  
x  
）权限。  
#### 符合模式  
  
符号模式使用字母和符号来表示权限的变化。基本格式如下：  
```
```  
- who  
：指定哪些用户类别的权限要改变。可以是以下一个或多个字母的组合：  
  
- u  
：用户（所有者）  
  
- g  
：组  
  
- o  
：其他用户（其他人）  
  
- a  
：所有用户（等同于   
ugo  
）  
  
- operator  
：指定如何改变权限。可以是以下一个符号：  
  
- +  
：添加权限  
  
- -  
：移除权限  
  
- =  
：设置权限  
  
- permissions  
：指定具体的权限。可以是以下一个或多个字母的组合：  
  
- r  
：读权限  
  
- w  
：写权限  
  
- x  
：执行权限  
  
#### 符号模式实例  
```
```  
- sudo  
：以超级用户（root）权限执行命令。这通常用于需要更高权限的操作。  
  
- chmod  
：更改文件或目录的权限。  
  
- u=rwx,g+rw,o-r  
：这是权限设置的具体部分，分为三个部分：  
  
- u=rwx  
：设置用户（所有者）的权限为读（  
r  
）、写（  
w  
）和执行（  
x  
）。  
  
- g+rw  
：给组增加读（  
r  
）和写（  
w  
）权限。  
  
- o-r  
：从其他用户（其他人）那里移除读（  
r  
）权限。  
  
- file  
：要更改权限的文件名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IsBqr7iatOVy9paqMOx2Hib5VYibe9mV71UMibzIFNMFD2NGqib11bdHYTag/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
- u+x,g+w,o-r  
：这是权限设置的具体部分，分为三个部分：  
  
- u+x  
：给用户（所有者）增加执行权限。  
  
- g+w  
：给组增加写权限。  
  
- o-r  
：从其他用户（其他人）那里移除读权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Ih6JUwgOptnZ55PBWRmaFqfO6CnapDdqljibCZZMSdNPyWZc7WelkIAw/640?wx_fmt=png&from=appmsg "")  
  
  
#### 八进制模式  
  
八进制模式使用数字来表示权限。每个权限类别（用户、组、其他用户）可以用一个八进制数字表示，范围从 0 到 7。每个数字的含义如下：  
- 4  
：读权限（  
r  
）  
  
- 2  
：写权限（  
w  
）  
  
- 1  
：执行权限（  
x  
）  
  
权限的组合可以通过将相应的数字相加得到：  
  
- 0  
：无权限  
  
- 1  
：执行权限（  
x  
）  
  
- 2  
：写权限（  
w  
）  
  
- 3  
：写和执行权限（  
wx  
）  
  
- 4  
：读权限（  
r  
）  
  
- 5  
：读和执行权限（  
rx  
）  
  
- 6  
：读和写权限（  
rw  
）  
  
- 7  
：读、写和执行权限（  
rwx  
）  
  
#### 八进制模式实例  
```
```  
- chmod  
：更改文件或目录的权限。  
  
- 400  
：权限模式，使用八进制数字表示。  
  
- file  
：要更改权限的文件名。  
  
- 用户（所有者）：  
r  
（读权限）  
  
- 组：  
-  
（无权限）  
  
- 其他用户（其他人）：  
-  
（无权限）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I4rUmL8El1icLwTw4SFuV3QArMuMylhiaz6PTyDU8GG9dmA0EGlwlXEDQ/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
  
权限变为对所有用户都完全开放  
- 用户（所有者）：  
rwx  
（读、写、执行）  
  
- 组：  
rwx  
（读、写、执行）  
  
- 其他用户（其他人）：  
rwx  
（读、写、执行）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IaEX58643ZVsDUhaUcEpeicLBia9iaJYqzKRzHI1rACBRD5iahvibC6EgDAQ/640?wx_fmt=png&from=appmsg "")  
  
  
## 日志相关  
### 一、系统日志相关命令  
```
```  
- ls  
: 这是一个基本的列表命令，用于列出目录内容。  
  
- -l  
: 这是一个选项，表示使用长格式（long format）列出文件信息。长格式会显示更多的细节，包括文件权限、所有者、组、大小、修改时间和文件名等。  
  
- /var/log  
: 这是要列出内容的目录路径。  
/var/log  
 目录通常包含系统的各种日志文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Ixv5Fp363ST1CO1367A7zHc9NfYRE228BrWWcKbhEVp6bQqgpojnzeQ/640?wx_fmt=png&from=appmsg "")  
### 二、认证信息日志相关命令  
```
```  
- sudo  
: 用于临时提升当前用户的权限，以便以超级用户（root）的身份执行命令。  
  
- tail  
: 用于显示文件的末尾部分。  
  
- -3  
: 指定要显示文件的最后 3 行。  
  
- /var/log/auth.log  
: 要查看的文件路径。  
/var/log/auth.log  
 通常是系统认证日志文件，记录了系统登录、权限验证等相关信息。  
  
### 三、二进制日志相关命令  
```
```  
1. **who /var/log/wtmp**  
:  
  
1. who  
 命令用于显示当前登录到系统的用户信息。  
  
1. /var/log/wtmp  
 是一个特殊的二进制文件，记录了所有用户的登录和注销信息。  
  
1. 通过指定   
/var/log/wtmp  
 作为参数，  
who  
 命令会从这个文件中读取登录记录。  
  
1. **|**  
:  
  
1. 管道符   
|  
 用于将前一个命令的输出作为后一个命令的输入。  
  
1. **tail -5**  
:  
  
1. tail  
 命令用于显示文件的末尾部分。  
  
1. -5  
 选项表示显示最后 5 行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IAF5ANAag4SXmg3rwljPtmXJmJzvtnXM6qJwf4dpWP4JGYmVQJP87iaA/640?wx_fmt=png&from=appmsg "")  
  
  
**详细解释**  
  
- **用户名**  
 (  
kali  
):  
  
- 这是登录到系统的用户名。在这个例子中，用户名是   
kali  
。  
  
- **终端**  
 (  
tty7  
):  
  
- tty7  
 是一个虚拟终端，通常用于图形界面。在 Linux 系统中，  
tty1  
 到   
tty6  
 通常用于文本模式的登录，而   
tty7  
 通常用于第一个图形会话。  
  
- **日期**  
 (  
2024-11-06  
):  
  
- 这是用户登录的日期。在这个例子中，用户在 2024 年 11 月 6 日登录。  
  
- **时间**  
 (  
10:40  
):  
  
- 这是用户登录的时间。在这个例子中，用户在 10:40 登录。  
  
- **附加信息**  
 (  
(:0)  
):  
  
- 这个信息表示图形会话的显示编号。  
(:0)  
 表示这是第一个图形会话。在多显示器或多用户环境中，可能会有多个显示编号，如   
:1  
、  
:2  
 等。  
  
### 四、dmesg  
  
用于显示内核环缓冲区（kernel ring buffer）的内容。这个缓冲区包含了系统启动时和运行过程中内核生成的各种消息，包括硬件检测、驱动程序加载、错误信息等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IkZXcYBPxOosKE3jdkVfBNwbTt8qE9M0pEj6JmHW9ksRxnd8PoUictMA/640?wx_fmt=png&from=appmsg "")  
  
### 五、systemd日志相关命令，journalctl  
- systemd是Linux系统的初始化系统和服务管理器， 使用   
journald  
 来收集和存储系统日志。  
  
journalctl  
 是   
systemd  
 提供的一个强大工具，用于查询和显示   
journald  
 日志。  
journald  
 是   
systemd  
 的日志管理服务，负责收集和存储系统日志。以下是对   
journalctl  
 命令的详细解释和常用选项。  
  
```
```  
- 显示今天所有日志  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I2TwyBmEy5Rm9ULAzheBfY17cNMQkHm4FCYqKY2xjbEvFyRc8ELRV5Q/640?wx_fmt=png&from=appmsg "")  
  
  
#### 1. 显示所有日志  
```
```  
  
这个命令会显示   
journald  
 中的所有日志条目。  
#### 2. 实时监控日志  
```
```  
  
这个命令会实时显示新的日志条目，类似于   
tail -f  
。  
#### 3. 按时间范围过滤  
- **显示最近 10 分钟的日志**  
：  
```
```  
  
- **显示今天的所有日志**  
：  
```
```  
  
- **显示昨天的所有日志**  
：  
```
```  
  
- **显示特定日期范围的日志**  
：  
```
```  
  
#### 4. 按服务过滤  
- **显示特定服务的日志**  
（例如   
sshd  
）：  
```
```  
  
- **显示多个服务的日志**  
：  
```
```  
  
#### 5. 按优先级过滤  
- **显示错误级别及以上的日志**  
：  
```
```  
  
- **支持的优先级**  
：  
  
- emerg  
（紧急）  
  
- alert  
（警报）  
  
- crit  
（严重）  
  
- err  
（错误）  
  
- warning  
（警告）  
  
- notice  
（通知）  
  
- info  
（信息）  
  
- debug  
（调试）  
  
#### 6. 按用户过滤  
- **显示特定用户的日志**  
：  
```
```  
  
#### 7. 按机器过滤  
- **显示特定机器的日志**  
：  
```
```  
  
#### 8. 按进程 ID 过滤  
- **显示特定进程的日志**  
：  
```
```  
  
#### 9. 按单元过滤  
- **显示特定单元的日志**  
：  
```
```  
  
#### 10. 显示日志条目的详细信息  
- **显示每条日志的详细信息**  
：  
```
```  
  
#### 11. 导出日志  
- **将日志导出为 JSON 格式**  
：  
```
```  
  
- **将日志导出为短格式**  
：  
```
```  
  
#### 12. 按字段过滤  
- **显示包含特定字段的日志**  
：  
```
```  
  
#### 13. 显示特定数量的日志条目  
- **显示最近 10 条日志**  
：  
```
```  
  
#### 14. 显示日志的简短格式  
- **显示日志的简短格式**  
：  
```
```  
  
#### 15. 显示日志的机器可读格式  
- **显示日志的机器可读格式**  
：  
```
```  
  
#### 显示 sshd 服务的最近 10 条日志  
```
```  
#### 实时监控 sshd 服务的日志  
```
```  
#### 显示昨天到今天的 sshd 服务日志  
```
```  
#### 显示错误级别及以上的日志  
```
```  
#### 导出 sshd 服务的日志为 JSON 格式  
```
```  
## 存储管理  
### 一、内存使用量，free  
  
free  
 命令是一个用于显示系统中物理内存（RAM）和交换空间（swap）使用情况的工具  
```
```  
  
**参数**  
  
**-b**  
- **功能**  
: 以字节（bytes）为单位显示内存使用情况。  
  
- **说明**  
: 这个选项适用于需要精确到字节的情况。  
  
**-k**  
  
- **功能**  
: 以千字节（kilobytes，KB）为单位显示内存使用情况。  
  
- **说明**  
: 这是   
free  
 命令的默认单位，适用于大多数情况。  
  
**-m**  
  
- **功能**  
: 以兆字节（megabytes，MB）为单位显示内存使用情况。  
  
- **说明**  
: 适用于需要以更大的单位显示内存使用情况的情况。  
  
**-g**  
  
- **功能**  
: 以千兆字节（gigabytes，GB）为单位显示内存使用情况。  
  
- **说明**  
: 适用于内存容量较大的系统，以更简洁的方式显示内存使用情况。  
  
**-h**  
  
- **功能**  
: 以人类可读的格式显示内存使用情况，自动选择合适的单位（KB、MB、GB）。  
  
- **说明**  
: 这个选项会根据内存的实际大小自动选择最合适的单位，使输出更易于阅读。  
  
**-l**  
  
- **功能**  
: 显示低内存（low memory）和高内存（high memory）的使用情况。  
  
- **说明**  
: 主要用于 32 位系统，现代 64 位系统通常不需要这个选项。低内存是指可以直接由内核管理的内存，高内存是指需要通过ZONE_HIGHMEM管理的内存。  
  
**-s <interval>**  
  
- **功能**  
: 持续显示内存使用情况，每隔指定的时间间隔（秒）显示一次。  
  
- **说明**  
: 适用于需要实时监控内存使用情况的场景。  
  
**-t**  
  
- **功能**  
: 在输出中添加一行总结，显示总内存、已用内存、空闲内存、共享内存、缓冲区和缓存。  
  
- **说明**  
: 这个选项会在输出的末尾添加一行总结，方便快速查看总体内存使用情况。  
  
**-o**  
  
- **功能**  
: 不显示缓冲区和缓存的内存使用情况。  
  
- **说明**  
: 适用于只需要查看基本内存使用情况，而不关心缓冲区和缓存的情况。  
  
**-V**  
  
- **功能**  
: 显示   
free  
 命令的版本信息。  
  
- **说明**  
: 适用于需要检查   
free  
 命令版本的情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ILMFauI8XdQxSCDZORZX5dg4oUKm9FaJ5735RfM6moauGDJCMaT92dQ/640?wx_fmt=png&from=appmsg "")  
  
  
**结果解释**  
  
- **物理内存**  
:  
  
- 总量：3888 MB  
  
- 已用：1108 MB  
  
- 空闲：2327 MB  
  
- 共享：12 MB  
  
- 缓冲/缓存：685 MB  
  
- 可用：2779 MB  
  
- **交换空间**  
:  
  
- 总量：974 MB  
  
- 已用：0 MB  
  
- 空闲：974 MB  
  
### 二、磁盘使用量，df  
  
df  
 命令用于显示文件系统的磁盘空间使用情况  
```
```  
- 显示文件系统的磁盘使用情况，并以人类可读的格式（自动选择合适的单位 KB、MB、GB）显示，同时显示每个文件系统的类型  
  
**参数**  
  
参数和free命令类似，没有-b(以字节为单位)参数，多了一些其他参数，比如-T(显示每个系统文件的类型)  
  
   
**-k**  
  
- **功能**  
: 以千字节（1K 字节）为单位显示磁盘使用情况。  
  
- **说明**  
: 这是默认的单位，但明确指定   
-k  
 可以确保输出单位一致。  
  
**-m**  
  
- **功能**  
: 以兆字节（1M 字节）为单位显示磁盘使用情况。  
  
- **说明**  
: 适用于需要以更大的单位显示磁盘使用情况的情况。  
  
**-h**  
  
- **功能**  
: 以人类可读的格式显示磁盘使用情况，自动选择合适的单位（KB、MB、GB）。  
  
- **说明**  
: 这个选项会根据磁盘的实际大小自动选择最合适的单位，使输出更易于阅读。  
  
**-B <size>**  
  
- **功能**  
: 以指定的块大小显示磁盘使用情况。  
  
- **说明**  
:   
<size>  
 可以是   
1  
（字节）、  
1K  
（千字节）、  
1M  
（兆字节）等。  
  
**-T**  
  
- **功能**  
: 在输出中添加一列，显示每个文件系统的类型（例如 ext4、xfs、btrfs 等）。  
  
- **说明**  
: 适用于需要查看文件系统类型的场景。  
  
**-P**  
  
- **功能**  
: 以 POSIX 格式输出，不显示标题行。  
  
- **说明**  
: 适用于需要标准格式输出的脚本或自动化任务。  
  
**-a**  
  
- **功能**  
: 显示所有文件系统，包括那些通常不显示的 dummy 文件系统。  
  
- **说明**  
: 适用于需要查看所有文件系统的详细信息的情况。  
  
**-x <filesystem_type>**  
  
- **功能**  
: 排除指定类型的文件系统。  
  
- **说明**  
: 例如，排除   
tmpfs  
 文件系统。  
  
**-t <filesystem_type>**  
  
- **功能**  
: 只显示指定类型的文件系统。  
  
- **说明**  
: 例如，只显示   
ext4  
 文件系统。  
  
**-l**  
  
- **功能**  
: 只显示本地文件系统。  
  
- **说明**  
: 适用于需要区分本地和网络文件系统的情况。  
  
**-i**  
  
- **功能**  
: 显示 inode 信息而不是块使用情况。  
  
- **说明**  
: 适用于需要查看文件系统中 inode 使用情况的情况。  
  
**-h --si**  
  
- **功能**  
: 以人类可读的格式显示磁盘使用情况，使用 1000 为基数（而不是 1024）。  
  
- **说明**  
: 适用于需要符合国际单位制的情况。  
  
**-x <filesystem_type> -t <filesystem_type>**  
  
- **功能**  
: 结合使用   
-x  
 和   
-t  
 选项，可以同时排除和包含特定类型的文件系统。  
  
- **说明**  
: 例如，排除   
tmpfs  
 文件系统，只显示   
ext4  
 文件系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I0pbgSqj2Oia7VBrwXN8oHy9VF4jBaKWdh9gibdlg6W1VI169MmC63feA/640?wx_fmt=png&from=appmsg "")  
  
  
### 三、文件或目录大小，du  
  
du  
 命令用于显示文件和目录的磁盘使用情况。它可以递归地显示目录下每个文件和子目录的大小，也可以显示单个文件的大小。  
```
```  
  
**参数**  
  
**-k**  
- **功能**  
: 以千字节（1K 字节）为单位显示磁盘使用情况。  
  
- **说明**  
: 这是默认的单位，但明确指定   
-k  
 可以确保输出单位一致。  
  
**-m**  
  
- **功能**  
: 以兆字节（1M 字节）为单位显示磁盘使用情况。  
  
- **说明**  
: 适用于需要以更大的单位显示磁盘使用情况的情况。  
  
**-h**  
  
- **功能**  
: 以人类可读的格式显示磁盘使用情况，自动选择合适的单位（KB、MB、GB）。  
  
- **说明**  
: 这个选项会根据磁盘的实际大小自动选择最合适的单位，使输出更易于阅读。  
  
**-b**  
  
- **功能**  
: 以字节为单位显示磁盘使用情况。  
  
- **说明**  
: 适用于需要精确到字节的情况。  
  
**-s**  
  
- **功能**  
: 显示总和，不显示每个文件和子目录的详细信息。  
  
- **说明**  
: 适用于只需要知道总磁盘使用情况的情况。  
  
**-a**  
  
- **功能**  
: 显示所有文件和目录，包括隐藏文件和目录。  
  
- **说明**  
: 适用于需要查看所有文件和目录的详细信息的情况。  
  
**-d <depth>**  
  
- **功能**  
: 限制递归的深度。  
  
- **说明**  
:   
<depth>  
 是一个整数，表示递归的层数。例如，  
-d 1  
 只显示当前目录下的子目录。  
  
**-S**  
  
- **功能**  
: 显示每个目录的大小，不包括子目录的大小。  
  
- **说明**  
: 适用于需要单独查看每个目录的大小的情况。  
  
**-c**  
  
- **功能**  
: 在输出中添加一行总结，显示总磁盘使用情况。  
  
- **说明**  
: 适用于需要查看总和的情况。  
  
**--exclude=<pattern>**  
  
- **功能**  
: 排除匹配特定模式的文件或目录。  
  
- **说明**  
:   
<pattern>  
 是一个通配符模式，例如   
*.log  
 会排除所有   
.log  
 文件。  
  
**-x**  
  
- **功能**  
: 仅显示同一文件系统上的文件和目录。  
  
- **说明**  
: 适用于需要区分不同文件系统的情况。  
  
**-l**  
  
- **功能**  
: 计算所有文件，即使它们有多个硬链接。  
  
- **说明**  
: 适用于需要准确计算所有文件大小的情况，即使有硬链接。  
  
**-H**  
  
- **功能**  
: 以 1000 为基数（而不是 1024）显示人类可读的格式。  
  
- **说明**  
: 适用于需要符合国际单位制的情况。  
  
**-L**  
  
- **功能**  
: 跟踪符号链接指向的文件。  
  
- **说明**  
: 适用于需要计算符号链接指向的文件的实际大小的情况。  
  
**-X <file>**  
  
- **功能**  
: 从指定文件中读取排除模式。  
  
- **说明**  
:   
<file>  
 是一个包含排除模式的文件，每行一个模式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6If6AGpv3icCGwqYMpeQFEhLCQXnKFfnjcRhGetLxmn1IO1dRlCMVSj4Q/640?wx_fmt=png&from=appmsg "")  
  
  
### 五、挂载分区，mount  
  
mount  
 命令用于将文件系统（如硬盘分区、USB驱动器、网络文件系统等）挂载到指定的挂载点，使其可以被访问，一般需要root权限  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IQr9PrM71gpUpy16Xsicib7KHrgAZ1CYrngqM5wZ6HUDuEpWxcMiaDvR4A/640?wx_fmt=png&from=appmsg "")  
```
```  
- **sudo**  
: 以超级用户权限执行   
mount  
 命令。  
  
- **mount**  
: 将文件系统挂载到指定的挂载点。  
  
- **/dev/sdb1**  
: 要挂载的设备，通常是硬盘或USB驱动器的分区。  
  
- **/mnt/usb**  
: 挂载点，即设备将被挂载到的目录。  
  
**参数**  
  
**-t <type>**  
  
- **功能**  
: 指定文件系统的类型。  
  
- **说明**  
: 用于指定要挂载的文件系统的类型，例如   
ext4  
、  
ntfs  
、  
vfat  
 等。  
  
**-o <options>**  
  
- **功能**  
: 指定挂载选项。  
  
- **说明**  
: 用于指定挂载时的各种选项，常见的挂载选项包括：  
  
- ro  
: 以只读方式挂载。  
  
- rw  
: 以读写方式挂载。  
  
- noexec  
: 不允许在挂载点上执行文件。  
  
- nosuid  
: 忽略文件的 setuid 和 setgid 位。  
  
- nodev  
: 不允许访问设备文件。  
  
- sync  
: 以同步方式写入数据。  
  
- async  
: 以异步方式写入数据。  
  
- uid=<user_id>  
: 指定文件系统的拥有者。  
  
- gid=<group_id>  
: 指定文件系统的所属组。  
  
- umask=<mask>  
: 设置文件系统的权限掩码。  
  
- fmask=<mask>  
: 设置文件的权限掩码。  
  
- dmask=<mask>  
: 设置目录的权限掩码。  
  
- codepage=<codepage>  
: 指定代码页（主要用于 FAT 文件系统）。  
  
- iocharset=<charset>  
: 指定字符集（主要用于 FAT 文件系统）。  
  
- shortname=<mode>  
: 设置短文件名模式（主要用于 FAT 文件系统）。  
  
- utf8  
: 使用 UTF-8 编码（主要用于 FAT 文件系统）。  
  
- errors=<mode>  
: 指定错误处理模式，例如   
errors=remount-ro  
（出错时重新以只读方式挂载）。  
  
**-a**  
  
- **功能**  
: 挂载   
/etc/fstab  
 文件中定义的所有文件系统。  
  
- **说明**  
: 适用于需要一次性挂载所有配置文件中定义的文件系统的情况。  
  
**-v**  
  
- **功能**  
: 显示详细信息。  
  
- **说明**  
: 适用于需要查看挂载过程中的详细信息的情况。  
  
**-r**  
  
- **功能**  
: 以只读方式挂载文件系统。  
  
- **说明**  
: 等同于   
-o ro  
。  
  
**-w**  
  
- **功能**  
: 以读写方式挂载文件系统。  
  
- **说明**  
: 等同于   
-o rw  
。  
  
**-L <label>**  
  
- **功能**  
: 按标签挂载文件系统。  
  
- **说明**  
: 适用于需要按文件系统的标签（label）挂载的情况。  
  
**-U <uuid>**  
  
- **功能**  
: 按 UUID 挂载文件系统。  
  
- **说明**  
: 适用于需要按文件系统的 UUID 挂载的情况。  
  
**-n**  
  
- **功能**  
: 不使用   
/etc/mtab  
 文件记录挂载信息。  
  
- **说明**  
: 适用于需要临时挂载且不希望记录到   
/etc/mtab  
 的情况。  
  
**-R**  
  
- **功能**  
: 递归挂载文件系统。  
  
- **说明**  
: 适用于需要递归挂载文件系统及其子文件系统的情况。  
  
**-i**  
  
- **功能**  
: 不执行任何实际操作，仅显示将要执行的挂载命令。  
  
- **说明**  
: 适用于需要模拟挂载操作的情况。  
  
**-f**  
  
- **功能**  
: 强制挂载，即使设备不可用也尝试挂载。  
  
- **说明**  
: 适用于需要强制挂载的情况。  
  
**-F <file>**  
  
- **功能**  
: 从指定文件中读取挂载选项。  
  
- **说明**  
: 适用于需要从文件中读取挂载选项的情况。  
  
## 基本网络枚举  
### 一、基本网络工具  
#### ifconfig  
```
```  
  
是一个用于配置和显示网络接口信息的命令行工具。它可以显示网络接口的P地址、子网掩码、MC地址等信息，还可以用于启动、停止或配置网络接口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ItZjaVH55rAHw82OGO8e9GWjQKYYddZ0lUtXKLN5K9rgnZ4icQPYnpww/640?wx_fmt=png&from=appmsg "")  
  
#### ip  
```
```  
  
也是用于查看和管理网络接口的命令。  
  
它提供了比ifconfig更详细和灵活的网络接口信息显示，包括接口的状态、IP地址、子网码、广播地址等。  
- **查看所有网络接口的状态**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IlsBCdjSJaODchvSKjYaz73yetHo25R83XD1yBaO2HTzSicpxXq5DT3g/640?wx_fmt=png&from=appmsg "")  
- **查看特定网络接口的状态**  
：  
  
```
```  
  
例如，查看  
eth0  
接口的状态：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IyZJaMVicSPoWQ1dEXQMwe1wBa5C3aU8oRLDibLNicfXyZqWUFFLebdyuw/640?wx_fmt=png&from=appmsg "")  
- **启用网络接口**  
：  
  
```
```  
  
例如，启用  
eth0  
接口：  
```
```  
- **禁用网络接口**  
：  
  
```
```  
  
例如，禁用  
eth0  
接口：  
```
```  
- **设置网络接口的IP地址**  
：  
  
```
```  
  
例如，为  
eth0  
接口设置IP地址  
192.168.1.100/24  
：  
```
```  
- **删除网络接口的IP地址**  
：  
  
```
```  
  
例如，删除  
eth0  
接口的IP地址  
192.168.1.100/24  
：  
```
```  
- **查看路由表**  
：  
  
```
```  
  
或者简写为：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6In5Z8ITp6DE0PA4KUYsWZvSbj0pv50ghAxQPWpPySlnHV46NfWSHlvw/640?wx_fmt=png&from=appmsg "")  
- **添加默认网关**  
：  
  
```
```  
  
例如，设置默认网关为  
192.168.1.1  
：  
```
```  
- **删除默认网关**  
：  
  
```
```  
  
假设你的默认网关是   
192.168.1.1  
，并且使用的是   
eth0  
 接口，你可以使用以下命令删除默认网关：  
```
```  
- **添加静态路由**  
：  
```
```  
  
例如，添加一个到  
10.0.0.0/8  
网络的路由，通过  
192.168.1.1  
网关，使用  
eth0  
接口：  
  
```
```  
- **查看ARP缓存**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ILhr9oeTR00U8GhcFPpUViatBXa7fHLXaUyCUWDFmIm3A1s8Prf4dpFw/640?wx_fmt=png&from=appmsg "")  
- **刷新ARP缓存**  
：  
  
```
```  
- **查看网络统计信息**  
：  
  
```
```  
  
例如，查看  
eth0  
接口的统计信息：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IAm6ZWMjETqbm0Js3xvggsxibWsD2HBUIiaPBvj2eMH9ZpCmas6jomhIQ/640?wx_fmt=png&from=appmsg "")  
#### ifdown  
  
ifdown  
 命令用于禁用网络接口。它通常与   
ifup  
 命令一起使用，用于启动和停止网络接口，上面的  
ip  
命令也可以实现网络接口管理  
```
```  
  
**参数**  
- **-f, --force**  
：强制禁用网络接口，即使出现错误也会继续执行。  
  
```
```  
- **-n, --noact**  
：模拟操作，显示将要执行的操作，但不实际执行。  
  
#### ifup  
```
```  
  
**参数**  
- -a  
 或   
--all  
：启动所有网络接口。  
  
- -v  
 或   
--verbose  
：显示详细的输出信息，有助于调试。  
  
- -n  
 或   
--no-act  
：模拟操作而不实际执行，用于测试配置是否正确。  
  
- -f  
 或   
--force  
：强制启动接口，即使该接口已经在运行中。  
  
- -i FILE  
 或   
--interfaces=FILE  
：指定一个不同于默认的接口配置文件。  
  
- --no-carrier-wait[=SECONDS]  
：在没有物理连接的情况下尝试启动接口，可选参数为等待的时间（秒）。  
  
### 二、网络配置  
#### /etc/network/interfaces  
```
```  
  
这是一个系统文件，用于配置网络接口的静态IP地址、子网掩码、网关等信息。  
  
在一些Liux发行版中，通过编辑这个文件可以实现网络接口的手动配置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IJojsFsHs4ZJL2wAr6jmoJ7d2MnjOrtDg3picGq3vhrMHyicC8MSdHUpw/640?wx_fmt=png&from=appmsg "")  
  
```
```  
- 这一行表示从   
/etc/network/interfaces.d/  
 目录中读取所有的配置文件。这样可以将不同的网络接口配置分散到多个文件中，便于管理和维护。  
  
```
```  
- auto lo  
：表示在系统启动时自动激活   
lo  
 回环接口。  
  
- iface lo inet loopback  
：定义   
lo  
 接口为回环接口，并使用   
inet  
 地址族。  
  
#### NetworkManager  
  
NetworkManager  
 作为一个系统服务，可以通过   
systemd  
 进行管理。  
  
**配置文件**  
  
NetworkManager  
 的配置文件通常位于   
/etc/NetworkManager/  
 目录下，主要包括以下几个文件和目录：  
- **/etc/NetworkManager/NetworkManager.conf**  
：主配置文件，用于配置   
NetworkManager  
 的全局设置。  
  
- **/etc/NetworkManager/system-connections/**  
：存储各个网络连接的配置文件。  
  
- **/etc/NetworkManager/conf.d/**  
：用于存放额外的配置文件，可以覆盖主配置文件中的设置。  
  
**检测是否启用NetworkManager服务**  
```
```  
  
如果状态显示为"active"或者"running",那么网络管理器已经成功启动了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IKMtZgbpawpkib0X5Gnp2WDPUKgTLPaU1RrKBCcqVkYIxBe9iaEPkxd5Q/640?wx_fmt=png&from=appmsg "")  
  
1. **启动 NetworkManager 服务**  
：  
  
```
```  
1. **停止 NetworkManager 服务**  
：  
  
```
```  
1. **启用 NetworkManager 服务**  
（开机自启）：  
  
```
```  
1. **禁用 NetworkManager 服务**  
：  
  
```
```  
#### nmcli  
  
nmcli  
 是   
NetworkManager  
 的主要命令行工具，提供了丰富的命令和选项来管理网络连接。  
##### 基本用法  
1. **查看网络状态**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IDCgyya0icWuAeOmhEZ9k3hUKD5ceMzPuRCvqCBUUJFFaVf8heykW6jA/640?wx_fmt=png&from=appmsg "")  
1. **列出所有网络设备**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IfRafnKu6FBENZCfoqxkmYicMq2RnrsmibhW4Z5e0w4ycADwT7uYK0hug/640?wx_fmt=png&from=appmsg "")  
1. **列出所有网络连接**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Ilicv0xtmpTnMqJf4SGl0EzJ98XOypRL1ewXP3hHEZSMClvVI2Slfqjw/640?wx_fmt=png&from=appmsg "")  
1. **连接到特定网络**  
：  
  
```
```  
1. **断开特定网络**  
：  
  
```
```  
1. **创建新的网络连接**  
：  
  
```
```  
1. **编辑现有网络连接**  
：  
  
```
```  
1. **删除网络连接**  
：  
  
```
```  
#### nmtui  
  
nmtui  
 是一个基于文本的用户界面，适用于没有图形界面的环境。  
1. **启动 nmtui**  
：  
  
```
```  
1. **连接到网络**  
：  
  
1. 选择 "Activate a connection" 选项。  
  
1. 选择要连接的网络设备和连接。  
  
1. **编辑网络连接**  
：  
  
1. 选择 "Edit a connection" 选项。  
  
1. 选择要编辑的连接并进行修改。  
  
1. **设置主机名和 DNS**  
：  
  
1. 选择 "Set system hostname" 选项。  
  
1. 输入新的主机名并保存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IpKFAUibgWcenMOn5aeTbfDrf2M2Q8JZfZgia7zibUla875CNicyYny4U4Q/640?wx_fmt=png&from=appmsg "")  
  
  
## 网络连接  
### 一、网络连接状态查看工具  
#### netstat  
```
```  
  
**选项**  
- **-a**  
：显示所有连接和监听端口。  
  
- **-n**  
：显示数字形式的地址和端口号，而不是尝试解析成主机名或服务名。  
  
- **-t**  
：显示 TCP 连接。  
  
- **-u**  
：显示 UDP 连接。  
  
- **-p**  
：显示每个连接的进程 ID (PID) 和程序名称。  
  
- **-r**  
：显示路由表。  
  
- **-i**  
：显示网络接口统计信息。  
  
- **-s**  
：显示每个协议的统计信息。  
  
- **-l**  
：显示监听的端口。  
  
- **-e**  
：显示扩展信息。  
  
- **-c**  
：连续显示网络连接信息，每秒刷新一次。  
  
```
```  
- **-n**  
：显示数字形式的地址和端口号，而不是尝试解析成主机名或服务名。  
  
- **-a**  
：显示所有连接和监听端口，包括 TCP 和 UDP。  
  
- **-t**  
：显示 TCP 连接。  
  
- **-u**  
：显示 UDP 连接。  
  
- **-p**  
：显示每个连接的进程 ID (PID) 和程序名称。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IGpI6WVrwv6t3CRVyfFLb3P39xxh2vMkbiaOHSaFXheicm8anaCIN7RiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
**输出字段解释**  
  
- **Proto**  
：协议类型（TCP 或 UDP）。  
  
- **Recv-Q**  
：接收队列中的数据包数量。  
  
- **Send-Q**  
：发送队列中的数据包数量。  
  
- **Local Address**  
：本地地址和端口号。  
  
- **Foreign Address**  
：远程地址和端口号。  
  
- **State**  
：连接状态（仅适用于 TCP 连接）。  
  
- **PID/Program name**  
：进程 ID 和程序名称。由于权限不足，这里显示为   
-  
  
#### ss  
  
ss  
（Socket Statistics）是一个用于显示套接字统计信息的命令行工具，它比传统的   
netstat  
 更高效，提供了更丰富的网络连接信息。  
ss  
 是   
iproute2  
 包的一部分，在大多数现代 Linux 发行版中都预装了这个工具。  
```
```  
  
**常用选项**  
- **-a**  
：显示所有连接，包括监听和非监听的。  
  
- **-t**  
：显示 TCP 连接。  
  
- **-u**  
：显示 UDP 连接。  
  
- **-n**  
：显示数字形式的地址和端口号，而不是尝试解析成主机名或服务名。  
  
- **-p**  
：显示每个连接的进程 ID (PID) 和程序名称。  
  
- **-l**  
：显示监听的端口。  
  
- **-i**  
：显示网络接口统计信息。  
  
- **-s**  
：显示每个协议的统计信息。  
  
- **-e**  
：显示扩展信息。  
  
- **-r**  
：显示路由信息。  
  
- **-m**  
：显示内存使用情况。  
  
- **-o**  
：显示定时器信息。  
  
- **-z**  
：显示零计数的连接。  
  
- **-A**  
：指定要显示的地址族，可以是   
all  
,   
inet  
,   
unix  
,   
packet  
,   
netlink  
 等。  
  
- **-4**  
：只显示 IPv4 连接。  
  
- **-6**  
：只显示 IPv6 连接。  
  
- **-f**  
：指定地址族，如   
inet  
（IPv4 和 IPv6），  
unix  
，  
packet  
 等。  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ItRniaFibgibdIbfd3tyQMYv7S38lNdxias4H9hE4CK3OVSSpAibfkArVo0g/640?wx_fmt=png&from=appmsg "")  
  
  
**解释**  
1. **UDP 连接**  
：  
  
1. **Local Address:Port**  
:   
192.168.80.136%eth0:68  
 — 本地 IP 地址   
192.168.80.136  
，端口   
68  
，通过   
eth0  
 网络接口。  
  
1. **Peer Address:Port**  
:   
192.168.80.254:67  
 — 远程 IP 地址   
192.168.80.254  
，端口   
67  
。这通常是 DHCP 服务器的地址和端口。  
  
1. **Process**  
:   
NetworkManager  
 进程（PID 680）正在使用这个连接，文件描述符为 27。  
  
1. **TCP 连接**  
：  
  
1. **Local Address:Port**  
:   
127.0.0.1:36065  
 — 本地回环地址   
127.0.0.1  
，端口   
36065  
。  
  
1. **Peer Address:Port**  
:   
0.0.0.0:*  
 — 没有远程地址和端口，表示这是一个监听端口，可以接受来自任何地址的连接。  
  
1. **Process**  
:   
containerd  
 进程（PID 992）正在使用这个连接，文件描述符为 9。  
  
### 二、二层地址查看工具  
#### arp  
```
```  
  
**常用选项**  
- -a  
：显示所有接口的 ARP 缓存条目。  
  
- -n  
：以数字形式显示地址，不进行域名解析。  
  
- -d  
：删除指定的 ARP 缓存条目。  
  
- -s  
：添加静态 ARP 缓存条目。  
  
- -i  
：指定网络接口。  
  
- -v  
：显示详细信息。  
  
- -e  
：以易于阅读的格式显示 ARP 缓存条目。  
  
```
```  
  
选项   
-e  
 表示以更易于阅读的格式显示 ARP 缓存中的条目，而   
-n  
 则表示以数字形式显示地址，而不是尝试解析主机名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ICbvV2CaEdwJoObiamDJ2FclQJcs6yhAbj2IaFG2ajQL2htickkK9UvHQ/640?wx_fmt=png&from=appmsg "")  
  
- **Address**  
: 192.168.80.2  
  
- 这是设备的 IP 地址。  
  
- **HWtype**  
: ether  
  
- 这表示硬件类型为以太网（Ethernet）。  
  
- **HWaddress**  
: 00:50:56:ff:b0:85  
  
- 这是设备的 MAC 地址。  
  
- **Flags**  
: C  
  
- 这个标志表示该 ARP 条目是动态创建的（Committed）。这意味着该条目是由系统自动添加的，并且会在一段时间后自动老化并删除。  
  
- **Mask**  
: （空）  
  
- 子网掩码，通常为空。  
  
- **Iface**  
: eth0  
  
- 这表示该 ARP 条目是通过   
eth0  
 接口获取的。  
eth0  
 通常是系统中的第一个以太网接口。  
  
### 三、路由信息相关工具  
#### route  
  
route  
 命令用于显示和操作 IP 路由表。路由表决定了数据包如何从一个网络传输到另一个网络。通过   
route  
 命令，可以查看当前的路由表、添加新的路由条目、删除现有的路由条目等。  
```
```  
  
**常用选项**  
- -n  
：以数字形式显示地址，不进行域名解析。  
  
- -v  
：显示详细信息。  
  
- -A  
 或   
-4  
：使用 IPv4 地址族。  
  
- -6  
：使用 IPv6 地址族。  
  
**常用命令**  
  
- add  
：添加新的路由条目。  
  
- del  
 或   
delete  
：删除现有的路由条目。  
  
- change  
：更改现有的路由条目。  
  
- replace  
：替换现有的路由条目。  
  
**实例**  
  
显示当前的路由表  
  
```
```  
  
查看详细的路由信息  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IEhrg85oSWmCPSmthMMNGmmZiaem12CDSMjhnhrgyh9j6Kc0OKHlMTpA/640?wx_fmt=png&from=appmsg "")  
- **Destination**  
：目标网络或主机的地址。  
  
- **Gateway**  
：到达目标网络或主机的下一跳网关地址。  
  
- **Genmask**  
：子网掩码。  
  
- **Flags**  
：  
  
- U  
：路由是活动的（Up）。  
  
- G  
：目标是网关。  
  
- H  
：目标是主机。  
  
- D  
：路由是动态添加的。  
  
- M  
：路由是修改过的。  
  
- **Metric**  
：路由的度量值，用于选择最佳路径。  
  
- **Ref**  
：路由引用计数。  
  
- **Use**  
：路由使用计数。  
  
- **Iface**  
：使用的网络接口。  
  
添加新的路由条目  
  
```
```  
- -net  
：指定目标是一个网络。  
  
- 192.168.2.0  
：目标网络的地址。  
  
- netmask 255.255.255.0  
：子网掩码。  
  
- gw 192.168.1.254  
：网关地址。  
  
- dev eth0  
：指定使用的网络接口。  
  
删除现有的路由条目  
```
```  
  
 添加默认路由  
```
```  
- default  
：表示默认路由。  
  
- gw 192.168.1.1  
：网关地址。  
  
- dev eth0  
：指定使用的网络接口。  
  
#### ip route  
- 显示当前的 IP 路由表  
  
**ip route 、ip route show、ip r之间的关系**  
  
ip route show  
 是   
ip route  
 的完整形式，明确指定了显示路由表的操作。虽然   
ip route  
 和   
ip route show  
 在大多数情况下是等价的，但   
ip route show  
 更加明确，更容易理解。  
ip r  
是简写  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6Iv1qKFibwNS35pe6fyPKZBmoskibBuZ0JWHaYRRfhdib24QX62UAw0Fhkg/640?wx_fmt=png&from=appmsg "")  
#### sudo ip route add/del  
  
**添加**  
```
```  
- **sudo**  
：以超级用户权限执行命令。添加或删除路由条目通常需要超级用户权限。  
  
- **ip**  
：调用   
ip  
 命令，这是一个多功能的网络配置工具。  
  
- **route add**  
：指定要添加一个新路由条目。  
  
- **10.13.37.0/24**  
：目标网络的地址和子网掩码。  
10.13.37.0/24  
 表示目标网络是   
10.13.37.0  
，子网掩码是   
255.255.255.0  
。  
  
- **dev eth1**  
：指定使用的网络接口。  
eth0  
 是目标网络   
10.13.37.0/24  
 所在的网络接口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IqajR9uEq49GqicVXe78AsdKpCcLUpn1FfXqyMGKRPSzUlLclSE02wUQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以已经加了到eth0中了  
  
**删除**  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IIW6gNxE9pYN1NYn8piamibAnicvrRJfZG56seiauv5ADu7DruKhgBAH2Fw/640?wx_fmt=png&from=appmsg "")  
### 四、路由跟踪工具  
  
traceroute:是一个用于跟踪数据包从本地主机到目标主机所经过的路由路径的工具。  
```
```  
  
**常用选项**  
- **-I**  
：使用 ICMP 协议（默认使用 UDP）。  
  
- **-T**  
：使用 TCP 协议。  
  
- **-m**  
：设置最大跳数（默认为 30）。  
  
- **-w**  
：设置超时时间（默认为 5 秒）。  
  
- **-q**  
：设置每次探测的次数（默认为 3 次）。  
  
- **-f**  
：设置第一个探测的 TTL 值（默认为 1）。  
  
- **-p**  
：设置 UDP 或 TCP 探测的端口号。  
  
- **-n**  
：以数字形式显示地址，不进行域名解析。  
  
- **-g**  
：指定中间网关（用于源路由）。  
  
- **-z**  
：设置两次探测之间的等待时间（以秒为单位）。  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IUAGev8TLnNA6umniank84agygicLSwmibueHcibibP3FPN5p9x1voQFmH6A/640?wx_fmt=png&from=appmsg "")  
## ssh服务  
  
ssh  
（Secure Shell）命令用于安全地远程登录到另一台计算机，并执行命令和传输文件。  
ssh  
 提供了加密的通信通道，确保数据传输的安全性。  
```
```  
  
**常用选项**  
- **-V**  
：显示   
ssh  
 版本信息。  
  
- **-v**  
：增加调试信息的详细程度，最多可以使用三次（-v -v -v）。  
  
- **-i**  
：指定用于身份验证的私钥文件。  
  
- **-p**  
：指定远程主机的 SSH 服务端口（默认为 22）。  
  
- **-l**  
：指定登录用户名。  
  
- **-X**  
 或   
**-Y**  
：启用 X11 转发，用于图形界面应用程序。  
  
- **-N**  
：不执行远程命令，仅建立连接（常用于端口转发）。  
  
- **-f**  
：在后台运行   
ssh  
。  
  
- **-C**  
：启用压缩。  
  
- **-o**  
：指定配置选项。  
  
- **-L**  
：本地端口转发。  
  
- **-R**  
：远程端口转发。  
  
- **-D**  
：动态端口转发（SOCKS 代理）。  
  
### 一、启动服务  
```
```  
### 二、连接主机  
```
```  
#### 1. 基本用法  
```
```  
- **user**  
：远程主机的用户名。  
  
- **hostname**  
：远程主机的地址（可以是 IP 地址或主机名）。  
  
#### 2. 指定端口  
```
```  
- **-p 2222**  
：指定远程主机的 SSH 服务端口为 2222。  
  
#### 3. 使用私钥文件  
```
```  
#### 4. 多跳连接  
```
```  
- **-t**  
：强制分配一个伪终端，用于多跳连接。  
  
#### 5. 代理命令  
```
```  
- **-o ProxyCommand="nc %h %p"**  
：使用   
nc  
（Netcat）作为代理命令。  
  
- **-i /path/to/private_key**  
：指定用于身份验证的私钥文件。  
  
### 三、配置文件  
```
```  
  
/etc/ssh/sshd_config  
 是 SSH 服务器（  
sshd  
）的配置文件，用于控制 SSH 服务的行为。这个文件包含了许多配置选项，可以通过编辑这些选项来调整 SSH 服务的各种行为。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I4MhORcIY6ymG8sdb4TPmiceVRMptG39JHqIpxwGNFWiavaI7RMtvHjDA/640?wx_fmt=png&from=appmsg "")  
  
  
**Port**  
- **描述**  
：指定 SSH 服务监听的端口号。  
  
- **默认值**  
：22  
  
- **示例**  
：  
  
```
```  
  
**ListenAddress**  
- **描述**  
：指定 SSH 服务监听的 IP 地址。可以指定多个地址，每行一个。  
  
- **默认值**  
：监听所有可用的 IP 地址  
  
- **示例**  
：  
  
```
```  
  
**HostKey**  
- **描述**  
：指定 SSH 服务使用的主机密钥文件。  
  
- **默认值**  
：通常包括   
ssh_host_rsa_key  
、  
ssh_host_dsa_key  
、  
ssh_host_ecdsa_key  
 和   
ssh_host_ed25519_key  
  
- **示例**  
：  
  
```
```  
1. **PermitRootLogin**  
  
- **描述**  
：控制是否允许 root 用户通过 SSH 登录。  
  
- **默认值**  
：  
prohibit-password  
  
- **可选值**  
：  
  
- yes  
：允许 root 登录  
  
- no  
：禁止 root 登录  
  
- without-password  
：允许 root 使用公钥认证登录，但不允许密码登录  
  
- prohibit-password  
：允许 root 使用公钥认证登录，但不允许密码登录  
  
- **示例**  
：  
  
```
```  
  
**PasswordAuthentication**  
- **描述**  
：控制是否允许使用密码进行身份验证。  
  
- **默认值**  
：  
yes  
  
- **可选值**  
：  
  
- yes  
：允许密码认证  
  
- no  
：禁止密码认证  
  
- **示例**  
：  
  
```
```  
  
**ChallengeResponseAuthentication**  
- **描述**  
：控制是否允许使用挑战-响应认证机制。  
  
- **默认值**  
：  
yes  
  
- **可选值**  
：  
  
- yes  
：允许挑战-响应认证  
  
- no  
：禁止挑战-响应认证  
  
- **示例**  
：  
  
```
```  
  
**PubkeyAuthentication**  
- **描述**  
：控制是否允许使用公钥进行身份验证。  
  
- **默认值**  
：  
yes  
  
- **可选值**  
：  
  
- yes  
：允许公钥认证  
  
- no  
：禁止公钥认证  
  
- **示例**  
：  
  
```
```  
  
   
**AuthorizedKeysFile**  
- **描述**  
：指定公钥文件的位置。  
  
- **默认值**  
：  
%h/.ssh/authorized_keys  
  
- **示例**  
：  
  
```
```  
### 四、客户端配置  
```
```  
  
在 SSH 客户端配置文件中，  
HashKnownHosts  
 选项用于控制是否对   
known_hosts  
 文件中的主机名和 IP 地址进行哈希处理。哈希处理可以增强安全性，因为即使   
known_hosts  
 文件被泄露，攻击者也无法直接从中获取实际的主机名或 IP 地址。  
#### 客户端配置文件  
  
SSH 客户端的配置文件通常位于   
~/.ssh/config  
，每个用户可以有自己的配置文件。系统范围的配置文件位于   
/etc/ssh/ssh_config  
。  
#### 配置 HashKnownHosts  
  
要启用   
HashKnownHosts  
 选项，你需要在   
~/.ssh/config  
 文件中添加或修改相应的配置。  
#### 示例配置  
1. **打开配置文件**  
：  
```
```  
  
1. **添加或修改 HashKnownHosts 选项**  
：  
```
```  
  
1. Host *  
：表示此配置适用于所有主机。  
  
1. HashKnownHosts yes  
：启用对   
known_hosts  
 文件中的主机名和 IP 地址进行哈希处理。  
  
#### 保存并应用配置  
1. **保存配置文件**  
：编辑完配置文件后，保存并退出编辑器。  
  
1. **测试配置**  
：  
  
```
```  
  
你也可以直接使用   
-o  
 选项在命令行中临时启用   
HashKnownHosts  
。  
#### 配置说明  
- **HashKnownHosts yes**  
：启用哈希处理。  
  
- **HashKnownHosts no**  
：禁用哈希处理（默认值）。  
  
#### nano退出命令  
1. **保存更改并退出**  
：  
  
1. 按   
Ctrl + O  
（写入文件，即保存）。  
  
1. 按   
Enter  
 确认保存。  
  
1. 按   
Ctrl + X  
 退出   
nano  
。  
  
1. **不保存更改并退出**  
：  
  
1. 按   
Ctrl + X  
。  
  
1. 当提示是否保存修改时，按   
N  
（不保存）。  
  
## 远程拷贝，scp  
  
scp  
（Secure Copy）命令用于在本地和远程主机之间安全地复制文件。  
scp  
 使用 SSH 协议进行加密传输，确保数据的安全性  
```
```  
  
**常用选项**  
- **-P**  
：指定远程主机的 SSH 服务端口（默认为 22）。  
  
- **-p**  
：保留文件的修改时间、访问时间和模式。  
  
- **-q**  
：静默模式，不显示传输进度。  
  
- **-r**  
：递归复制目录。  
  
- **-C**  
：启用压缩。  
  
- **-i**  
：指定用于身份验证的私钥文件。  
  
- **-v**  
：增加调试信息的详细程度。  
  
#### 示例  
  
**远程主机 1.1.1.1 上的 /home/kali/.bashrc 文件复制到本地当前目录下的 Copiedbashrc 文件**  
```
```  
- **root@1.1.1.1**  
：指定远程主机的用户名和 IP 地址。  
  
- root  
：远程主机的用户名。  
  
- 1.1.1.1  
：远程主机的 IP 地址。  
  
- **/home/kali/.bashrc**  
：远程主机上的源文件路径。  
  
- **Copiedbashrc**  
：本地目标文件名  
  
**将本地文件 passwd 复制到远程主机的 /home/kali 目录下**  
  
```
```  
  
详细解释  
- **scp**  
：命令本身，用于安全复制文件。  
  
- **-p**  
：保留文件的修改时间、访问时间和模式。  
  
- **passwd**  
：本地文件的路径。  
  
- **root@127.0.0.1:/home/kali/**  
：远程主机的用户名、IP 地址和目标路径。  
  
## 历史命令，history  
  
history  
 命令用于查看和操作 shell 命令历史记录。不同的 shell（如 Bash、Zsh 等）可能有不同的历史记录功能，但大多数 shell 都提供了类似的功能。下面是对   
history  
 命令的详细解释，包括基本用法、常用选项和示例。  
```
```  
  
**常用选项**  
- **无选项**  
：默认情况下，  
history  
 命令会显示当前 shell 会话的历史记录。  
  
- **-c**  
：清除当前 shell 会话的历史记录。  
  
- **-d 偏移量**  
：删除指定偏移量的历史记录条目。  
  
- **-a**  
：将当前会话的新命令追加到历史记录文件中。  
  
- **-r**  
：从历史记录文件中读取命令并将其添加到当前会话的历史记录中。  
  
- **-w**  
：将当前会话的历史记录写入历史记录文件。  
  
- **-n**  
：从历史记录文件中读取新命令并将其添加到当前会话的历史记录中。  
  
#### 1. 查看历史记录  
```
```  
- **输出**  
：显示当前 shell 会话的历史记录，每行包括一个编号和一条命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I2Npgibb20eMsrt7LUdAIzZZk1uiacibpmsib8qhwJaibcDIkunhtFCUfXMw/640?wx_fmt=png&from=appmsg "")  
  
  
#### 2. 查看最近的 10 条命令  
```
```  
- **输出**  
：显示最近的 10 条命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I5EMBVn1kjb4pqsgSq2iaP3o0exPR0z79deU7aETiaHMiaACqpeDvuEKEA/640?wx_fmt=png&from=appmsg "")  
  
  
#### 3. 清除历史记录  
```
```  
- **效果**  
：清除当前 shell 会话的历史记录。  
  
#### 4. 删除指定偏移量的历史记录条目  
```
```  
- **效果**  
：删除编号为 5 的历史记录条目。  
  
#### 5. 将当前会话的新命令追加到历史记录文件中  
```
```  
- **效果**  
：将当前会话的新命令追加到历史记录文件中（通常是   
~/.bash_history  
）。  
  
#### 6. 从历史记录文件中读取命令并添加到当前会话  
```
```  
- **效果**  
：从历史记录文件中读取命令并将其添加到当前会话的历史记录中。  
  
#### 7. 将当前会话的历史记录写入历史记录文件  
```
```  
- **效果**  
：将当前会话的历史记录写入历史记录文件中。  
  
#### 8. 从历史记录文件中读取新命令并添加到当前会话  
```
```  
- **效果**  
：从历史记录文件中读取新命令并将其添加到当前会话的历史记录中。  
  
#### 历史记录文件  
- **Bash**  
：默认的历史记录文件是   
~/.bash_history  
。  
  
- **Zsh**  
：默认的历史记录文件是   
~/.zsh_history  
。  
  
  
## linux目录介绍  
```
```  
## 基本命令详解  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I3pTwHdBZ0DMM5oEibpntxp0skFZdgezkGAbJnldXuIXD9nV0ug3dA9g/640?wx_fmt=png&from=appmsg "")  
```
```  
### useradd和adduser  
```
```  
```
```  
#### useradd 命令  
- **功能**  
：  
useradd  
 是一个低级别的用户账户管理工具，它主要用于添加新的用户到系统中。  
  
- **特点**  
：  
  
- 它是一个命令行工具，通常没有提供交互式的提示。  
  
- 使用   
useradd  
 创建的用户不会自动设置密码，需要通过   
passwd  
 命令来设置用户的密码。  
  
- 可以通过命令行参数指定许多选项，如用户的主目录、登录 Shell、用户 ID (UID) 等。  
  
- **示例**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IrteOv72qcuCcqOUrIwxoDIwQauctvzMyUv9dARFCiazILaN1VspUwqA/640?wx_fmt=png&from=appmsg "")  
#### adduser 命令  
- **功能**  
：  
adduser  
 实际上是   
useradd  
 的一个包装脚本，它提供了更友好的用户界面来创建新的用户账户。  
  
- **特点**  
：  
  
- adduser  
 通常会提供更多的默认值，使得创建用户更加简单。  
  
- 它可以自动设置用户的密码，并且在创建过程中可能会询问一些关于用户的额外信息（比如全名等）。  
  
- 在某些发行版中，  
adduser  
 与   
useradd  
 的行为完全相同，但在其他发行版中，它提供了更多的功能和更好的用户体验。  
  
- **示例**  
：  
  
```
```  
  
可以发现创建的用户目录没有任何文件，可以使用exit退出  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IRDLlHuylBDm3XbiaibJv2Lex8f44gb5swMK9C48BTj9qSAc2TU4JViazg/640?wx_fmt=png&from=appmsg "")  
  
  
**总结**  
- 如果你需要对创建的用户进行详细的配置，或者需要自动化脚本来创建用户，那么   
useradd  
 可能更适合你。  
  
- 如果你想要一个更简单的、交互式的体验来创建用户，那么   
adduser  
 是一个更好的选择。  
  
### userdel和deluser  
  
deluser  
 和   
userdel  
 命令在 Unix 或 Linux 系统中用于删除用户账户。虽然这两个命令的功能相似，但在实际使用中存在一些差异。  
#### userdel 命令  
- **功能**  
：  
userdel  
 是一个低级别的用户账户管理工具，用于删除用户账户。  
  
- **特点**  
：  
  
- 它是一个命令行工具，通常没有提供交互式的提示。  
  
- 默认情况下，  
userdel  
 只删除用户账户，不会删除用户的主目录和邮件目录。  
  
- 可以通过命令行参数指定删除用户的主目录和邮件目录。  
  
- **示例**  
：  
  
```
```  
```
```  
- 删除用户  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IfkdnzmF8UR2zwDvUYusPQAj3IPtFxotic0LLRRTkibXZcVAedbs5M94w/640?wx_fmt=png&from=appmsg "")  
  
  
这个时候还没有完全删除，还存在他的目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IekvaX5DXoPcicDC5Ak2GsAqh1CXKQMbFqQsh7BxYBCZdJ7MeYu33paQ/640?wx_fmt=png&from=appmsg "")  
  
  
使用彻底删除  
```
```  
#### deluser 命令  
- **功能**  
：  
deluser  
 是   
userdel  
 的一个包装脚本，提供了更友好的用户界面来删除用户账户。  
  
- **特点**  
：  
  
- deluser  
 通常会提供更多的默认值，使得删除用户更加简单。  
  
- 它可以自动处理删除用户的主目录和邮件目录。  
  
- 在某些发行版中，  
deluser  
 与   
userdel  
 的行为完全相同，但在其他发行版中，它提供了更多的功能和更好的用户体验。  
  
- **示例**  
：  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IUiauibTx99gBMwFsicBmNKPpRkicYiamnCRbp3j9k8vNRGVibTvqtdy8JvJw/640?wx_fmt=png&from=appmsg "")  
```
```  
  
**总结**  
- **userdel**  
：  
  
- 适用于需要低级别控制的情况。  
  
- 需要显式指定删除主目录和邮件目录的选项。  
  
- 通常在大多数 Linux 发行版中都可用。  
  
- **deluser**  
：  
  
- 提供更友好的用户界面和更多的默认选项。  
  
- 自动处理删除主目录和邮件目录的选项。  
  
- 在某些发行版（如 Debian 和 Ubuntu）中更为常见。  
  
#### 使用 userdel 删除用户并删除主目录  
```
```  
#### 使用 deluser 删除用户并删除主目录  
```
```  
## Linux资源耗尽病毒  
  
使用alert或notify-send等工具发送通知。  
```
```  
  
**解释：**  
  
**#!/bin/bash**  
- 它告诉操作系统这个脚本应该用   
/bin/bash  
 解释器来执行。  
/bin/bash  
 是 Bash 命令解释器的路径。  
  
**while语法**  
```
```  
  
这是一个无限循环。  
while true  
 会一直执行循环体中的代码，直到手动中断（例如按   
Ctrl+C  
）。  
  
**notify-send**  
 是一个命令行工具，用于发送桌面通知。它通常在 GNOME 桌面环境中可用。这里有两个参数：  
- 第一个参数   
"无限弹窗"  
 是通知的标题。  
  
- 第二个参数   
"这是一个无限循环的弹窗"  
 是通知的内容。  
  
**sleep 2**  
 命令会让脚本暂停 2 秒钟。  
  
保存这个脚本到一个文件中，比如  
无尽弹窗.sh  
,然后给它执行权限  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IQQiczMkVPkZfeZJYkHltvYJp59v7kqbMwrzQBJzuYdMkpSNuZlnvljg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/87Olcpibr0Aamwsf2ge5kBknFzXSdzvuSjFslj1IJEVcQp7em28DMTkbbPqPiasRnJvPyEiauMxTw97q6gJmMfeUA/640?wx_fmt=jpeg&from=appmsg "")  
  
适合想走渗透和红队方向的师傅，含金量比国内的高了不少。如果和我一样学历不太好的师傅，凭借这个可以抹平211的学历差距，感兴趣的师傅可以扫描加我微信，保证全网最低价oscp+的培训，而且是7年红队经验，红队队长带领培训  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AbTSVfgeVKzqQDQ40lWWAqhML49WnhmbfdgPWl4GepaeKDhszsHLOF6rrWDCBJiaicrOtZBrteKu0Ng/640?wx_fmt=png&from=appmsg "")  
  
可以关注一下关注公众号，里面有大量的工具和课程免费提供  
  
可以加入一下我们的帮会，是真正的红队大佬创建的，里面会定时丢些网上没有的工具（比如安卓远控7.4，不过现在已经删除了，有时限，加入的记得看好时间），除了这个：还有大量的poc、渗透工具、渗透课程、实战案例等等。现在只要99就可以终身，后面人多了就会涨价了    
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/87Olcpibr0Aamwsf2ge5kBknFzXSdzvuS6A52pib8JbNYOcasVyicSj1KYRYhT7LEvIn1BSaVjcAe986GZXXEMnLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
大量的课程和工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IYY5ibyoicicZgxmMibUsvumBl0cspxgVmCfLm8FN5DSibMms7UNaaUxMPMQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IRBKxFIrhYVX8JIhpe5P8rKDUOuThgPticwxWDI43fDc6aygyxZgUEicQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IN0KR2tNRhkNCvU7qbsjbs2x25AUR3nDdu9jprmmlb9rb06Jdzzzj5Q/640?wx_fmt=png&from=appmsg "")  
  
一些工具，二开的网恋避险工具（不清楚的可以去搜一下，黑客网络避险工具）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6I0pCSPoayMrRmpkOIymia5UkQEyMyDgKw8wtdicIeMZbwYGUJgV6F9G9A/640?wx_fmt=png&from=appmsg "")  
  
还有大量内部整理POC合集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IYhjEqIAsWUjCaOFq9NqEOeZSibVTfU0lhNMMUYE9q5Cpc0g1obJRMfA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6IU9F2q1CKNykPFGTkhJnaTdJV90cH3ThrovTqVUliaqEq9w85QBwMmtw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/87Olcpibr0AZvzZIbxibPWbHEYdGdqzV6ISN7eHlKGRjK0cLh8yK3xCy1iaXm9UP2d2CQRFDJC37d1rYIACEFGonw/640?wx_fmt=png&from=appmsg "")  
  
我们红队全栈公益课链接：  
https://space.bilibili.com/350329294  
  
  
