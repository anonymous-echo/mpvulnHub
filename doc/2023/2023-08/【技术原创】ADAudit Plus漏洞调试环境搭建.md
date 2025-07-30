#  【技术原创】ADAudit Plus漏洞调试环境搭建   
原创 3gstudent  嘶吼专业版   2023-08-07 12:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmQKh0tGuXrh5GDd7oic50CzYSDQiavrLH0Zv1CK7rhNzaibM7IDCWa6xiaA/640?wx_fmt=png "")  
      

    0x00 前言  
  
本文记录从零开始搭建ADAudit Plus漏洞调试环境的细节，介绍数据库用户口令的获取方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmQKh0tGuXrh5GDd7oic50CzYSDQiavrLH0Zv1CK7rhNzaibM7IDCWa6xiaA/640?wx_fmt=png "")  
      

    0x01 简介  
  
本文将要介绍以下内容：  
  
ADAudit Plus安装  
  
ADAudit Plus漏洞调试环境配置  
  
数据库用户口令获取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmQKh0tGuXrh5GDd7oic50CzYSDQiavrLH0Zv1CK7rhNzaibM7IDCWa6xiaA/640?wx_fmt=png "")  
      

    0x02 ADAudit Plus安装  
  
**1.下载**  
  
全版本下载地址：https://archives2.manageengine.com/active-directory-audit/  
  
**2.安装**  
  
安装参考：https://www.manageengine.com/products/active-directory-audit/quick-start-**guide-overview.html**  
  
**3.测试**  
  
访问https://localhost:8081  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmQKh0tGuXrh5GDd7oic50CzYSDQiavrLH0Zv1CK7rhNzaibM7IDCWa6xiaA/640?wx_fmt=png "")  
      

    0x03 ADAudit Plus漏洞调试环境配置  
  
方法同Password Manager Pro漏洞调试环境配置基本类似  
  
**1.开启调试功能**  
  
(1)定位配置文件  
  
查看java进程的信息，这里分别有两个java进程，对应两个不同的父进程wrapper.exe，如下图  
  
wrapper.exe的进程参数分别为：  
  
“C:\Program Files\ManageEngine\ADAudit Plus\bin\Wrapper.exe” -c “C:\Program Files\ManageEngine\ADAudit Plus\bin\..\conf\wrapper.conf”  
  
“C:\Program Files\ManageEngine\ADAudit Plus\bin\wrapper.exe” -s “C:\Program Files\ManageEngine\ADAudit Plus\apps\dataengine-xnode\conf\wrapper.conf”  
  
这里需要修改的配置文件为C:\Program Files\ManageEngine\ADAudit Plus\conf\wrapper.conf  
  
(2)修改配置文件添加调试参数  
  
找到启用调试功能的位置：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmJ1GqulaHYUOZsS9800D6pp4Sx9BfE04Yc791JxERRqIKnJwibdnhUYw/640?wx_fmt=png "")  
  
将其修改为  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmjR6dQVLVmdG5jtjWiaxVaEyUSgr1zibHzzgVe4U87VicqZ4W5PicDwKH3g/640?wx_fmt=png "")  
  
注：  
  
序号需要逐个递增，此处将wrapper.java.additional.3=-Xdebug修改为wrapper.java.additional.25=-Xdebug  
  
(3)重新启动相关进程  
  
关闭进程wrapper.exe和对应的子进程java.exe  
  
在命令行下执行命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmnc1EtRdpxQ5rucRRhJJeOAzibibTYQ5bnjexkHEOLvmZ3V6Ul4urdHHw/640?wx_fmt=png "")  
  
**2.常用jar包位置**  
  
路径：C:\Program Files\ManageEngine\ADAudit Plus\lib  
  
web功能的实现文件为AdventNetADAPServer.jar和AdventNetADAPClient.jar  
  
**3.IDEA设置**  
  
设置为Remote JVM Debug，远程调试成功如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmiaRSicNfuSFASRonZqv0L3rbPaicCnVicCZjiaIkzvCV1SVYDdaXI8vxhPw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmQKh0tGuXrh5GDd7oic50CzYSDQiavrLH0Zv1CK7rhNzaibM7IDCWa6xiaA/640?wx_fmt=png "")  
      

    0x04 数据库用户口令获取  
  
默认配置下，ADAudit Plus使用postgresql存储数据，默认配置了两个登录用户：adap和postgres  
  
**1.用户adap的口令获取**  
  
配置文件路径：C:\Program Files\ManageEngine\ADAudit Plus\conf\database_params.conf，内容示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAm91wn7lPO6fyDLuyr1vaYnZhtGZ0taEeeb3a2lcNt6WC9r8PEzNpSZg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAm4ibqHXjhYS4yjWjbzzlZEM32A8qh3KGhIAOuMmzU0TEicIPMrdcjgnicQ/640?wx_fmt=png "")  
  
其中，password被加密，加解密算法位于：C:\Program Files\ManageEngine\ADAudit Plus\lib\framework-tools.jar中的com.zoho.framework.utils.crypto->CryptoUtil.class  
  
经过代码分析，得出以下解密方法：  
  
密钥固定保存在C:\Program Files\ManageEngine\ADAudit Plus\conf\customer-config.xml，内容示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmRKvzPNZiaqJeuf7iaKL1g7k42z6bSnr7xTmkoSVt1hXoRIgWOIf1AMfQ/640?wx_fmt=png "")  
  
得到密钥：CryptTag为8ElrDgofXtbrMAtNQBqy  
  
根据以上得到的密文cb26b920b56fed8d085d71f63bdd79c55ea7b98f8794699562c06ea1bedbec52087b394f和密钥8ElrDgofXtbrMAtNQBqy，编写解密程序，代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmlqQWsicOpicppzrFZ4ldDib8S7c1gpBRCiaMicfhfTwCG2ICkRfic9tcWMlg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmF639DEqrqSAOF6iboYxiaM8ibNfiaI0rPpqicQqlWGotdPsriciaOpKwm7ZCg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmonBHXdvvFdQd1qQiaVTH9J7PdsLGTdzIApNCks3eWlW9JEHjFlRKAAA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmG4eiauk9xAicXMsI6IlH3FDeSYPtuERYN4gPibVTnm7oOg31LfvYSIPYg/640?wx_fmt=png "")  
  
程序运行后得到解密结果：Adaudit@123$  
  
拼接出数据库的连接命令："C:\Program Files\ManageEngine\ADAudit Plus\pgsql\bin\psql" "host=127.0.0.1 port=33307 dbname=adap user=adaudit password=Adaudit@123$"  
  
连接成功，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAm2gVHRyicTrHp1DH82tGBHia7rteFP4NbDqibBgNiaUNwbSJ2fSWMlbiaKKQ/640?wx_fmt=png "")  
  
**2.用户postgres的口令获取**  
  
口令硬编码于C:\Program Files\ManageEngine\ADAudit Plus\lib\AdventnetADAPServer.jar中的com.adventnet.sym.adsm.common.server.mssql.tools->ChangeDBServer.class->isDBServerRunning()，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmaYulVeBHCiaDWyr6znNwKNmywrWicdgLebqgCrx4oNbtwGmQoNRhGwyg/640?wx_fmt=png "")  
  
得到用户postgres的口令为Stonebraker  
  
拼接出数据库的连接命令："C:\Program Files\ManageEngine\ADAudit Plus\pgsql\bin\psql" "host=127.0.0.1 port=33307 dbname=adap user=postgres password=Stonebraker"  
  
连接成功，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAm2Via5EKzDqLuJJldoMNjnjS8ib5GQbXkTKyVbjCLZgR7YqtibMLsM1fbg/640?wx_fmt=png "")  
  
一条命令实现连接数据库并执行数据库操作的命令示例："C:\Program Files\ManageEngine\ADAudit Plus\pgsql\bin\psql" --command="SELECT * FROM public.aaapassword ORDER BY password_id ASC;" postgresql://postgres:Stonebraker@127.0.0.1:33307/adap  
  
返回结果示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAm7hCpoEJMJbqCD0asdfUrBVfHaVRleRTiaWFUenMSVllUExCMSHIflwQ/640?wx_fmt=png "")  
  
发现password的数据内容被加密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmQKh0tGuXrh5GDd7oic50CzYSDQiavrLH0Zv1CK7rhNzaibM7IDCWa6xiaA/640?wx_fmt=png "")  
      

    0x05 小结  
  
在我们搭建好ADAudit Plus漏洞调试环境后，接下来就可以着手对漏洞进行学习。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o299Fh5jKFeDAKOM59wtezAmOapdEicUicCVxXQhibsA35YxVvvZFOfVyTonGoQicjZSjjr9iaE3PfGb4zA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
