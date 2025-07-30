#  【技术原创】Veeam Backup & Replication漏洞调试环境搭建   
原创 3gstudent  嘶吼专业版   2023-07-28 12:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
# 0x00 前言  
  
本文以CVE-2023-27532为例，介绍Veeam Backup & Replication漏洞调试环境的搭建方法。  
# 0x01 简介  
  
本文将要介绍以下内容：  
  
环境搭建  
  
调试环境搭建  
  
数据库凭据提取  
  
CVE-2023-27532简要分析  
# 0x02 环境搭建  
  
**1.软件安装**  
  
安装文档：https://helpcenter.veeam.com/archive/backup/110/vsphere/install_vbr.html  
  
软件下载地址：https://www.veeam.com/download-version.html  
  
License申请地址：https://www.veeam.com/smb-vmware-hyper-v-essentials-download.html  
  
下载得到iso文件，安装时需要使用邮箱获得的License文件  
  
**2.默认目录**  
  
安装目录：C:\Program Files\Veeam\  
  
日志路径：C:\ProgramData\Veeam\Backup  
  
**3.默认端口**  
  
Veeam.Backup.Service ports: 9392,9401(SSL)  
  
Veeam.Backup.ConfigurationService port: 9380  
  
Veeam.Backup.CatalogDataService port: 9393  
  
Veeam.Backup.EnterpriseService port：9394  
  
Web UI ports: 9080,9443(SSL)  
  
RESTful API ports: 9399,9398(SSL)  
# 0x03 调试环境搭建  
  
**1.定位进程**  
  
执行命令：netstat -ano |findstr 9401  
  
返回结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkE8Bh0vMH8ey5QYk2YMenBTazVPk0R3pvUuClFoUaPW9SgwCvYLyrDOw/640?wx_fmt=png "")  
  
定位到进程pid为7132，进程名称为Veeam.Backup.Service.exe  
  
使用dnSpy Attach到进程Veeam.Backup.Service.exe  
  
**2.调试设置**  
  
为了在Debug过程中能够查看变量内容，需要创建以下文件：  
  
C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Service.ini  
  
C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.DBManager.ini  
  
C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.ServiceLib.ini  
  
C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Interaction.MountService.ini  
  
内容为：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEvjt7iaC93uVIWt3Qn8e2JN8NpibicRYs5QtHL29antWTOl5oAFmMN2uDQ/640?wx_fmt=png "")  
# 0x04 数据库凭据提取  
  
**1.获得数据库连接配置**  
  
(1)获得数据库连接端口  
  
打开SQL Server 2016 Configuration Manager，选择SQL Server Services，可以看到SQL Server(VEEAMSQL2016)对应的Process ID为1756，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkE1sk4fI85YmUZ8uUcfCPufes9xiap4kroIrbWOtVzAoSDY7LxUYXzrcA/640?wx_fmt=png "")  
  
查看进程对应的端口：  
netstat -ano|findstr 1756  
  
返回结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEFU9FOxGBxvUKCxJH3025TQxZQwBHp2HicZ1avZJOgF331a1nu1XIiblg/640?wx_fmt=png "")  
  
得到连接端口49720  
  
(2)获得数据库名称  
  
方法1：  
  
进入Configuration Database Connection Settings，在页面中可以看到Database name为VeeamBackup，认证方式为Windows Authentication，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEQRZQwKbzxfL848n8ps6eCxy0woP2ur9FPlQ9A6uArtfC8ywdKByJBQ/640?wx_fmt=png "")  
  
方法2:  
  
读取注册表键值：REG QUERY "HKEY_LOCAL_MACHINE\SOFTWARE\Veeam\Veeam Backup and Replication" /v SqlDatabaseName  
  
**2.数据库连接**  
  
(1)使用界面程序  
  
这里使用DbSchema  
  
选择SqlServer，配置如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEuCfmrnPBT71vdQ3DcHQ6ldzbDreXa8QvdDLuKUTWyoSlMNEvg1QdbQ/640?wx_fmt=png "")  
  
成功连接如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEGlax1XXmho426rd2WlSxsicuJttTszk6C8zvWmpayIygv7gic6bScRzA/640?wx_fmt=png "")  
  
数据库选择VeeamBackup.dbo，进入数据库页面，全局搜索关键词password，得到相关的查询语句：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEUn8KVwSXZXhSTaRFCnmlPtibKQMDg40fYgqiafiaaoKulicw5ea1GZmf9w/640?wx_fmt=png "")  
  
执行后获得数据库存储的凭据信息，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEIqSDBzQEiaw8e7fIjzFDuiaYxoOOEBvMFwWUhzOlNmTXdU0VnKpM9yZQ/640?wx_fmt=png "")  
  
(2)使用Powershell  
  
参考资料：https://github.com/sadshade/veeam-creds  
  
veeam-creds在Veeam Backup and Replication 11及更高版本测试时会报错，提示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEOGSroIahv45EWJTdrDXCIH8PLVDXM9M07ZX5hBA1ic1drEr7HG7Uxqg/640?wx_fmt=png "")  
  
这是因为https://github.com/sadshade/veeam-creds/blob/main/Veeam-Get-Creds.ps1#L32处使用了sqloledb，当前系统的sqloledb已经过期  
  
这里可以选择使用MSOLEDBSQL或MSOLEDBSQL19解决  
  
查看当前系统是否安装MSOLEDBSQL或MSOLEDBSQL19的Powershell命令：(New-Object System.Data.OleDb.OleDbEnumerator).GetElements() | select SOURCES_NAME, SOURCES_DESCRIPTION  
  
返回结果示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEu56hGdq8zrOuLw3pe51wKiaawyxNz2ibJr5JzDpy6EIcNuVn0DDjhHIA/640?wx_fmt=png "")  
  
以上结果显示当前系统安装了MSOLEDBSQL19，所以只需要将sqloledb替换为MSOLEDBSQL19即可  
# 补充：安装MSOLEDBSQL或MSOLEDBSQL19的方法  
  
下载地址：https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?source=recommendations&view=sql-server-ver16  
  
命令行安装方法：msiexec /i msoledbsql.msi /qn IACCEPTMSOLEDBSQLLICENSETERMS=YES  
  
安装前需要满足Microsoft Visual C++ Redistributable版本最低为14.34  
  
查看Microsoft Visual C++ Redistributable版本的简单方法：  
  
通过文件夹名称获得：dir /o:-d "C:\ProgramData\Package Cache"  
  
返回结果示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEx2zKsBHpLWBkBkIxQ84kIib1XwrlwT5q4SWXn7qSxAIEqTcP8pvriajA/640?wx_fmt=png "")  
  
从中可以得出Microsoft Visual C++ Redistributable版本为14.29.30037，需要安装更高版本的Microsoft Visual C++ Redistributable，下载地址：https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170  
  
x86和x64均需要安装，veeam-creds运行成功如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEDQw06pVaiciaoQFaJOWet3nY82O1licg42B2FTeV7v8qaR07iaocvQ5Wug/640?wx_fmt=png "")  
# 0x05 CVE-2023-27532简要分析  
  
Y4er公布了调用CredentialsDbScopeGetAllCreds获得明文凭据的POC:https://y4er.com/posts/cve-2023-27532-veeam-backup-replication-leaked-credentials/  
  
**1.凭据位置**  
  
此处的明文凭据对应的位置为：Veeam Backup & Replication Console->Manage Credentials，默认明文口令为空，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEB7lSalC343XWRrEVPSVbDIpadkVRkkUQJTpR9XkV3wFuOITn8DUgIA/640?wx_fmt=png "")  
  
调试断点位置为Veeam.Backup.DBManager.dll->CCredentialsDbScope，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkE159icA1jBoIr7spdDzrjx3FLuSJ5spicSSWXFOmDBjDtajaGOGVRrVsg/640?wx_fmt=png "")  
  
**2.数据解析**  
  
POC最终的返回结果为序列化之后的xml，将ParamValue作Base64解密后可以看到明文数据，但是格式不对，存在乱码  
  
这里可以调用Veeam自带的dll反序列化数据，得到正确的格式  
  
格式化输出字符串的代码示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEhKBmUEmeSF5v4mKYPZxYlIpr0XGjQCNAwuSbFE4MibC2ZTmQJjj7N7w/640?wx_fmt=png "")  
  
需要引用dll文件：  
  
Veeam.Backup.Common.dll  
  
Veeam.Backup.Configuration.dll  
  
Veeam.Backup.Interaction.MountService.dll  
  
Veeam.Backup.Logging.dll  
  
Veeam.Backup.Model.dll  
  
Veeam.Backup.Serialization.dll  
  
Veeam.TimeMachine.Tool.dll  
  
编译生成的文件需要在本地安装Veeam的环境下使用，否则报错提示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkE5sbD559Vz0ao3y6n0mQMZnfHrsSDUxA3hc9piaA5EVIEayznC5WmXlQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEthZXiboQCScsP97aNo8XIsicLLLiasmDYBty536leqHNlKkAuZ4GvNdWw/640?wx_fmt=png "")  
  
程序成功执行的结果示例如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkExaXiccU4I1Hs2ul6nDyV6P49xwyIvYoibojqgnB0MpRgqickoPscxflTg/640?wx_fmt=png "")  
  
本文以CVE-2023-27532为例，介绍搭建Veeam Backup & Replication漏洞调试环境的相关问题和解决方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEkaTOtar3pr3nHuVs9ic6vJHtuO5CNCMyehYDLcXsibpt03JavBQmwK8g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28Zyb83DIUXXvmgbHEr5JkEWAgCry9CjkO1KD5HFrGwfZCkicu4vsAZOzu9YN9SuzxetakEcYn9p0A/640?wx_fmt=png "")  
  
  
