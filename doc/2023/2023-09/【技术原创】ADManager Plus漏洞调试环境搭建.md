#  【技术原创】ADManager Plus漏洞调试环境搭建   
原创 3gstudent  嘶吼专业版   2023-09-12 12:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
# 0x00 前言  
  
本文记录从零开始搭建ADManager Plus漏洞调试环境的细节，介绍数据库用户口令的获取方法。  
# 0x01 简介  
  
本文将要介绍以下内容：  
- ADManager Plus安装  
  
- ADManager Plus漏洞调试环境配置  
  
- 数据库用户口令获取  
  
- 数据库加密算法  
  
# 0x02 ADManager Plus安装  
  
**1.下载**  
  
全版本下载地址：https://archives2.manageengine.com/ad-manager/  
  
**2.安装**  
  
安装参考：https://www.manageengine.com/products/ad-manager/help/getting_started/installing_admanager_plus.html  
  
**3.测试**  
  
访问https://localhost:8080  
# 0x03 ADManager Plus漏洞调试环境配置  
  
方法同ADAudit Plus漏洞调试环境配置基本类似  
  
**1.开启调试功能**  
  
(1)定位配置文件  
  
查看java进程的父进程wrapper.exe的进程参数为："C:\Program Files\ManageEngine\ADManager Plus\bin\Wrapper.exe" -c "C:\Program Files\ManageEngine\ADManager Plus\bin\\..\conf\wrapper.conf"  
  
这里需要修改的配置文件为C:\Program Files\ManageEngine\ADManager Plus\conf\wrapper.conf  
  
(2)修改配置文件添加调试参数  
  
找到启用调试功能的位置：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9cfGzuLG4cqroia8bPRFrcc9nq0DF6Xq5vsyWIynJsGeIibU0Wcr2HcHg/640?wx_fmt=png "")  
  
将其修改为  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9aptrJ2DYoXKe3O32iaz0OeAZichR7gMkjJq72QDCQgB1sFbO0mGSPzmA/640?wx_fmt=png "")  
  
(3)重新启动相关进程  
  
关闭进程wrapper.exe和对应的子进程java.exe  
  
在开始菜单依次选择Stop ADManager Plus和Start ADManager Plus  
  
**2.常用jar包位置**  
  
路径：C:\Program Files\ManageEngine\ADManager Plus\lib  
  
web功能的实现文件为AdventNetADSMServer.jar和AdventNetADSMClient.jar  
  
**3.IDEA设置**  
  
设置为Remote JVM Debug，远程调试  
# 0x04 数据库用户口令获取  
  
默认配置下，ADManager Plus使用postgresql存储数据，默认配置了两个登录用户：admanager和postgres  
  
**1.用户admanager的口令获取**  
  
配置文件路径：C:\Program Files\ManageEngine\ADManager Plus\conf\database_params.conf，内容示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9dztCJHYozfL94moUUnKofMdBxNvUQs4T7Ftyno1BBVgpMxjsRUkpkg/640?wx_fmt=png "")  
  
其中，password被加密，加解密算法位于：C:\Program Files\ManageEngine\ADManager Plus\lib\framework-tools.jar中的com.zoho.framework.utils.crypto->CryptoUtil.class  
  
经过代码分析，得出以下解密方法：  
  
密钥固定保存在C:\Program Files\ManageEngine\ADManager Plus\conf\customer-config.xml，内容示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9CgUADIlpcLs8THfv0ibdkD7zkpCqfVgBeOiaXt6sxdTgNk2ynHnDH4Sg/640?wx_fmt=png "")  
  
得到密钥：CryptTag为o0hV5KhXBIKRH2PAmnCx  
  
根据以上得到的密文28e3e4d73561031fa3a0100ea4bfb3617c7d66b631ff54ca719dd4ca3dcfb3c308605888和密钥o0hV5KhXBIKRH2PAmnCx，编写解密程序，代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9qRKEsmROIqDNM2sZJVm4xmfq8XXTyQotqDvkKBpQ6YFk6K76gqV0bw/640?wx_fmt=png "")  
  
程序运行后得到解密结果：DFVpXge0NS  
  
拼接出数据库的连接命令："C:\Program Files\ManageEngine\ADManager Plus\pgsql\bin\psql" "host=127.0.0.1 port=33306 dbname=adsm user=admanager password=DFVpXge0NS"  
  
**2.用户postgres的口令**  
  
默认口令为Stonebraker  
# 0x05 数据库加密算法  
  
**1.相关数据库信息**  
  
(1)用户相关的表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9PUVEsfGxv5IGIBfzk881XYyANyiayQQlNahLwxLl2ajTWTddyUx5y0A/640?wx_fmt=png "")  
  
(2)口令相关的表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9TvI0Orp3yGfMdLUgHzAaTn2cXmx2MySZfDwVXIlFLzUG8kofKicJqpg/640?wx_fmt=png "")  
  
(3)权限相关的表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE95G3MmHzeCbW3lccDLHTiaaxOTgqrSE3l4xeg9iaiah7pyFzv9XZntA6tA/640?wx_fmt=png "")  
  
**2.口令加密算法**  
  
算法同ADAudit Plus一致，计算密文的测试代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9MmlKYicGy990FZO5B8SaZdMSwqcuA9pTW4CjpOayS0VbV56YKPDmLeQ/640?wx_fmt=png "")  
  
计算结果为$2a$12$sdX7S5c11.9vZqC0OOPZQ.9PLFBKubufTqUNyLbom2Ub13d573jhi，同数据库得到的password项一致  
  
**3.语法示例**  
  
(1)查询用户及对应的权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9r9Otn936wtNxRAxnrHy2YoibVbm03EPoFd55M1CIdvxhPibsHFGTvA1g/640?wx_fmt=png "")  
  
(2)查询用户及对应的口令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9IXLFD2nJPqoEU5vV43xOCUicKQiaPN5ngS8B618MdnU0MW9QHnSgmEpw/640?wx_fmt=png "")  
  
(3)修改口令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9MmExNxJr7Ovb7FhtYoEA7UWdicLGSgIibCT8WIHPrBKhHxVWR1gClOZw/640?wx_fmt=png "")  
# 0x06 小结  
  
在我们搭建好ADManager Plus漏洞调试环境后，接下来就可以着手对漏洞进行学习。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9qm7tebNvhahe7X1RQdCXuIkBt9IriccNib7PQlNZqHfOKvhvficW10gug/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iclBGZRj1BwcpWorCFJGGE9XpxAVVB1BYw2WKrcD3BMs5fdwnLPibHpv0sIAR7stMckNDO8emJl5vQ/640?wx_fmt=png "")  
  
