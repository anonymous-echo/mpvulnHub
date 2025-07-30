#  【技术原创】Server Backup Manager漏洞调试环境搭建   
原创 3gstudent  嘶吼专业版   2023-04-19 12:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3trGSv0GlrADEdicIfOoOKUSiaiaYibxiaT9bjw3HFSqVH3W5vb83zVkUDiblw/640?wx_fmt=png "")  
      

    0x00 前言  
  
Server Backup Manager(SBM)是一种快速、经济且高性能的备份软件，适用于物理和虚拟环境中的Linux和Windows服务器。本文将要介绍Server Backup Manager漏洞调试环境的搭建方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3trGSv0GlrADEdicIfOoOKUSiaiaYibxiaT9bjw3HFSqVH3W5vb83zVkUDiblw/640?wx_fmt=png "")  
      

    0x01 简介  
  
本文将要介绍以下内容：  
  
环境搭建  
  
调试环境搭建  
  
用户数据库文件提取  
  
CVE-2022-36537简要介绍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3trGSv0GlrADEdicIfOoOKUSiaiaYibxiaT9bjw3HFSqVH3W5vb83zVkUDiblw/640?wx_fmt=png "")  
      

    0x02 环境搭建  
  
安装参考资料：http://wiki.r1soft.com/display/ServerBackupManager/Install+and+Upgrade+Server+Backup+Manager+on+Debian+and+Ubuntu.html  
  
参考资料提供了两种安装方法，但是我在测试过程中均遇到了缺少文件/etc/init.d/cdp-server的错误  
  
这里改用安装旧版本的Server Backup Manager，成功完成安装，具体方法如下：  
  
**1.下载安装包**  
  
http://r1soft.mirror.iweb.ca/repo.r1soft.com/release/6.2.2/78/trials/R1soft-ServerBackup-Manager-SE-linux64-6-2-2.zip  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tG4KwtRPeUjrvInHwgXKxkah0g6rTggUUW3fxj0fPApMNp2KynzmIwQ/640?wx_fmt=png "")  
  
web管理页面有以下两个:  
  
http://127.0.0.1:8080  
  
https://127.0.0.1:8443  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3trGSv0GlrADEdicIfOoOKUSiaiaYibxiaT9bjw3HFSqVH3W5vb83zVkUDiblw/640?wx_fmt=png "")  
      

    0x03 调试环境搭建  
  
研究过程如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tfMseb3rILxqynW1jq1qgVh2vxQEEvtX19LpGHz4xLS2TicAicqV6AoQg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3t8srJRH5iaRgkDxAGedf5LzbSOK88LSq39PkaiaakIsArF0IBicnUax5jA/640?wx_fmt=png "")  
  
(6)  
  
使用IDEA下断点并配置远程调试，远程调试成功如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3twBDicfm6wfxOia7D2Rxanic32IWYlotJmmqwicdibIHBUWeXpib1LKibRbicPA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3trGSv0GlrADEdicIfOoOKUSiaiaYibxiaT9bjw3HFSqVH3W5vb83zVkUDiblw/640?wx_fmt=png "")  
  
      
  
0x04 用户数据库文件提取  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tTVUyIgxwsfuWopZJvNnTicwjakEZKyeZnqLwLQm7icEEI6002tm8jF3w/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tDSUKJzbxHeqZSauWtGqZA7tQSNIBn2nQfmrqpY3UD8KlZA2ZSORXMA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tLrYDuxeD2xU1oTXpdYZENm288FAeBibBSblLRIH4T7ACR5F4jbbgkLw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tQ29MAoKgqB3Hucqzk0pcbibwqmbtJ4huIAia30CrVTkbGBkadmdOyQRA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tRsXk5hxcgFVibib4ywsXqqr36UOYLw2AUcDfRynbHcKwqEHWGvbExqrg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tbIlnjz5s0YRm4MjeEvP1qqfGicS0tUz6ZLic1WPj1l55ibgfukzlADV4g/640?wx_fmt=png "")  
  
  
从以上代码可以得出用户口令的加密算法  
  
(2)定位用户创建的具体代码实现位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3t0h5iaJGNdVyia5c6hicLHmMs0SRKz92iaB2K3jBxnLwmEmpWichxWGpHctQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tTOSoubaricfqv22g72iby7axwb6K0z2Rdc7Pjfzr1TmfmBnv3vPPpXtQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tYsHzFTpFW8tB8TDuWyrdUl8LstRtHKal3yWR7r2RGU6QOtSgS1d2Ng/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tZ3K5tj1kLzBCbkrv6UnrAHibkR9ZicdApQ6QfeWg1ALRcIuPTeSUto7g/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3twX1RxicWMTiayDCRNicHOlG60PFY5A1pZwmIsNplO5W3zA1HiaLBXNT8ew/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tKxWwtZF2byCUMzpR3EaH1xDDZia8bgewdSx7TmdkcdBriaW2l1hkOFqA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3te8kGFxJEXCn7BV74wf7CBrPxmro3vYcTEric3bXgbqLjaQCEysB6EYQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3trGSv0GlrADEdicIfOoOKUSiaiaYibxiaT9bjw3HFSqVH3W5vb83zVkUDiblw/640?wx_fmt=png "")  
      

    0x05 CVE-2022-36537简要介绍  
  
漏洞分析文章：https://medium.com/numen-cyber-labs/cve-2022-36537-vulnerability-technical-analysis-with-exp-667401766746  
  
文章中提到触发RCE需要上传一个带有Payload的com.mysql.jdbc.Driver文件  
  
这个操作只能利用一次，原因如下：  
  
默认情况下，管理后台的的Database Driver页面存在可以上传的图标，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tk7ENXyicZERicAibgELOp4eXVAAaQn7rpibblqiaLt1byS8JwrUYmbHibcUQ/640?wx_fmt=png "")  
  
上传后不再显示可上传的图标，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3tjWicrv3fxJzBxicmxLPFBzhfiaHEEOlcbR1TH8yy7ToCpydHoGZmQ305w/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3t0yBPpicG62ozOjjdZuET6UrNtOiaq06Wicuf0aVmllS0F22Ytde1mYRQA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3trGSv0GlrADEdicIfOoOKUSiaiaYibxiaT9bjw3HFSqVH3W5vb83zVkUDiblw/640?wx_fmt=png "")  
      

    0x06 小结  
  
本文介绍了在搭建Server Backup Manager调试环境过程中一些问题的解决方法，分析用户数据库文件提取的方法，给出检测CVE-2022-36537的建议。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzA5Puk0xbkZibJDcPazx3teWOQQK0KjEeZcAHP6Z3Cf2Mcy1icdYCx3ia1Klr9VAiaEQicyAk9licd1pw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
