#  【技术原创】vRealize Log Insight漏洞调试环境搭建   
原创 3gstudent  嘶吼专业版   2023-06-12 12:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3eQm8JY4FnKia4fus4PtDZA3C9zNbALLpYpE7yMyfpblzibYWdAL8eXSg/640?wx_fmt=png "")  
      

    0x00 前言  
  
本文记录从零开始搭建vRealize Log Insight漏洞调试环境的细节。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3eQm8JY4FnKia4fus4PtDZA3C9zNbALLpYpE7yMyfpblzibYWdAL8eXSg/640?wx_fmt=png "")  
      

    0x01 简介  
  
本文将要介绍以下内容：  
  
vRealize Log Insight安装  
  
vRealize Log Insight漏洞调试环境配置  
  
数据库操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3eQm8JY4FnKia4fus4PtDZA3C9zNbALLpYpE7yMyfpblzibYWdAL8eXSg/640?wx_fmt=png "")  
      

    0x02 vRealize Log Insight安装  
  
参考资料：https://docs.vmware.com/en/vRealize-Log-Insight/index.html  
  
**1.下载OVA文件**  
  
下载页面：https://customerconnect.vmware.com/evalcenter?p=vr-li  
  
下载前需要先注册用户，之后选择需要的版本进行下载  
  
**2.安装**  
  
(1)在VMware Workstation中导入OVA文件  
  
(2)配置  
  
访问配置页面https://  
  
选择Starting New Deployment，设置admin用户口令  
  
**3.开启远程调试功能**  
  
(1)查看所有服务的状态  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3JUQXgkqJSrYGib5fticswvEErRLlvqP1dPBepmplsy9olwL7cMmLicH4Q/640?wx_fmt=png "")  
  
结果如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3btpC0xBFdicx5jjBiblemwyVPicYAEL65wepNwD7Qxk8tcwXzGx79ia5RQ/640?wx_fmt=png "")  
  
定位到web相关的服务为loginsight.service  
  
(2)查看loginsight.service的具体信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3R1FJNGpmanvlD7wzERQWzeLRicnQ9yZ1oqWWg5G3Pu3icj7ica9rMrwzg/640?wx_fmt=png "")  
  
结果如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3qt5DDQLYJSb4q0GUVPEGcWEa5cibN19uu952090F8z1mFYfxgic0o14g/640?wx_fmt=png "")  
  
定位到服务启动文件：/usr/lib/loginsight/application/bin/loginsight  
  
(3)查看进程参数  
  
执行命令：ps aux|grep java  
  
返回结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3iaxBeiaKZyLHVS49FTOQ7weAbgzW8n8rGsUPV0Gn4FUqsnKm2X7KDK2Q/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3DZia3lC9nCcYYVStYRlK05FIvW71ORgTV5DzeAiciaiapBLGzSxlTU0hNQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3WiaXuXforOebLuv3wJWU9EqRZ9hlgnUR9DfiaI3VJkOB4mJ4hKZmia2iag/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3odarOnbYDwILo4xt616I8fDNCRW4U1nFuLHTRiacjSUrcqj93B7dDPA/640?wx_fmt=png "")  
  
结果分析如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3sooD8BVqFUPzd1n1HGGk8EjWVsib4ibtTTgovd6oLTCP3VaT7Pgmevicg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3cTYsibgJ54NruPiaGYCsDNxAbLNbJiaGicHR031ATdTcLjk6n2M10IAp7Q/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3eQm8JY4FnKia4fus4PtDZA3C9zNbALLpYpE7yMyfpblzibYWdAL8eXSg/640?wx_fmt=png "")  
      

    0x03 数据库操作  
  
**1.重置web登陆用户admin口令**  
  
实现文件：/usr/lib/loginsight/application/sbin/li-reset-admin-passwd.sh  
  
从文件中可以获得数据库操作的相关信息，如下图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3eEIbOXicvvwuj9dl0NBDr6sIVbKxzSZx60QSNGia964ic5q29ROK4hR7g/640?wx_fmt=png "")  
  
**2.连接数据库的命令参数**  
  
实现文件：/usr/lib/loginsight/application/lib/apache-cassandra-3.11.11/bin/cqlsh-no-pass  
  
文件内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3lE9Baia6llOkecp5Lib1wAqVTmn2chtPFzQmsfFuZQxuSibQ6T0MOvPibw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3P0ekVr6IKexd7Pb9K4t58CmKEB8ebzh5EaxUPwopPoukYR98d5WVlw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3XibasK6NrQzg82kdaO4nv5ia1SIxZ9LLb6CpoR9B2uySPAUlx409ic8icQ/640?wx_fmt=png "")  
**3.连接数据库的用户名口令**  
  
****  
**4.连接数据库的配置信息**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v36vFic4SJGoFfeLibnRbmiaAADvgq1oicF3fNdicAnrIrVFq2Q6bMC0XbpHQ/640?wx_fmt=png "")  
  
(1)使用封装好参数的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v30pwDsV4WiaW99VSxCOoPdtiaAz2EaiarduMxj1w3GiasYr2zibnpnuZIcZQ/640?wx_fmt=png "")  
  
(2)使用参数连接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3wb5NYCibhjgevlVic2dKiaqIWFcV8jhKu0nXOJRLk2PNa47SiaLsvfaNfA/640?wx_fmt=png "")  
  
从返回结果可以看到数据库使用了CQL(Cassandra Query Language)  
  
查询用户配置的命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v32xcYbsn9enoPDA0FZyCib1JX75nUA7EtjuASav3F9QwUEBrFDiaurx3Q/640?wx_fmt=png "")  
  
**5.界面化操作数据库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3CeuwzFsn8jCAQDibicBicz8DcMtJwrKdDchlCwaptJW4NICwZ1icAm9uCg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v35pkSE8FJUnjBRbWR4wpg2hEvgqNtdwmq0m9Myd8BvibKia7GlM1KK9MA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v3eQm8JY4FnKia4fus4PtDZA3C9zNbALLpYpE7yMyfpblzibYWdAL8eXSg/640?wx_fmt=png "")  
      

    0x04 小结  
  
在我们搭建好vRealize Log Insight漏洞调试环境后，接下来就可以着手对漏洞进行学习。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o280ZjWRHbG3AeBb0tGAf7v38URyJb0C7qUcTTk933by6dnvWEMMm0YjicPdzlU7aKlyUqdsgf6fnWw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
