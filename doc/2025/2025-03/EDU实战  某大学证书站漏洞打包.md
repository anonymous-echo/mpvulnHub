#  EDU实战 | 某大学证书站漏洞打包   
 青萍安全   2025-03-10 22:57  
  
    之前发现手里的供应链源码刚好某个证书站也有用到，随即代码审计  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvhVeHp71WgKY7rDSoM7LqbE7gcEkWSlYWDcaicDjoCXX8XlKVl7tVlqQ/640?wx_fmt=png&from=appmsg "")  
  
某处处理文件上传的  
getShowimages方法没有对文件后缀名进行检查，导致任意文件上传getshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvMadCyfibeAN0JfeT5urWtQ0PmtBOia0UvIs71KlphTEIdxXd5wlficowA/640?wx_fmt=png "")  
  
构造文件上传数据包，贴上免杀马数据包以后发包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvx32CddJUsz2JhqIEibcCzm2OAwXbXOhsz5D5AhdWnKtzGzwDZdoV4icg/640?wx_fmt=png&from=appmsg "")  
  
成功上传文件，访问空白看来是被解析了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvTr55eBcfScwHeUrKOlnWZBG09wQoS6vOUAVvtlhbGQuibu8CicribcXgw/640?wx_fmt=png&from=appmsg "")  
  
当前主机权限为www，使用suggest脚本查找可提权的exp，使用脏牛提权失败，随之使用4034提权成功，就到这了吗？由于src不允许后渗透的操作，我们使用其学校自带的vpn隧道连进去，账号密码就用之前收集下来的  
  
成功  
进入学校内网之后准备  
连接ssh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvibAy9hIOdvRG802wg53yMEEmEd3icQghDmB0VpoAPcxRGTbaZLHGameQ/640?wx_fmt=png "")  
  
双网卡主机通过nginx反向代理到外网去，通10段和192段，先做一下本机后渗透  
，  
8  
888  
端口开放  
bt服务，  
使用  
命令查看  
bt默认密码：  
/etc/init.d/bt default  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvJlHeNLiaw25CXqKUwgeJFtDT2EE2VC5r6ia67s3IJicyJxXswy7vQ638Q/640?wx_fmt=png&from=appmsg "")  
  
成功登陆宝塔  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvlJBbus3xSPVAQtAgJpHujGuFTV9Gxmd4pks2aGr1picm5qnaqPvqBOA/640?wx_fmt=png&from=appmsg "")  
  
通过这台  
双网卡主机进入  
10  
大段，指纹识别一波  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUv6Oa2C8vzld2ibYqcMpJ77uiaQNlia4ZibYhFYNv5xRAcgwerpic30c38m6Q/640?wx_fmt=png&from=appmsg "")  
  
使用任意文件上传getshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvYMXkEqbwRcB2UZ64pEaUEsvYH1pXBTD5QVnPoMlvC8XmGm3j1ibE8rg/640?wx_fmt=png&from=appmsg "")  
  
后渗透获取控制台密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvDIYtp2PYVrTucp0PmxFHwgpKKAbhEaNy7x7n8sEwpKsmpFOKWcXqnQ/640?wx_fmt=png&from=appmsg "")  
  
  
成功登陆后台获取很多其他网段主机信息，通过对某内网群控系统的0day攻击，获取到了以下成果  
  
禅道：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvKu6Z9YdUMUhFiasaiaqTICJGDhjXbVR3E2QqbCgtzwLam1PibZEzBcUxA/640?wx_fmt=png&from=appmsg "")  
  
某段下的一台主机通过密码碰撞直接进入ZenTao后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvOIRdPFWKmX1oiaT98OGcOUeoz1yicUibCsib9UREUGgUViaty9lClyr72KQ/640?wx_fmt=png&from=appmsg "")  
  
数据库连接信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUviaCCUmGhvSpsfSHaAlic1xKW5wsqT64a0PgvMIlZtibcAChHFyhNiaIhiaw/640?wx_fmt=png&from=appmsg "")  
  
ssh连接密码获取直接连接目标主机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvI69eViaYRfD8rob2zr9Ogv2TAcJ3jWFQgQ7ZibZjH2Ke6zWPyFudcPdw/640?wx_fmt=png&from=appmsg "")  
  
内网shiro：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUv4o29oRQkLT7V0pRLRSCg3picHIC3QDiaAblPYFSI0CGsRsTj63gqQTAA/640?wx_fmt=png&from=appmsg "")  
  
指纹识别到了shiro特征  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvsPBRXQiaEXnqc0ABeCfEFFPuYN21vaESIzTxqJWYsiawpFKHL5qYuDeA/640?wx_fmt=png&from=appmsg "")  
  
使用shiro自定义扩展key跑目标  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvIC2cKV9X6ial57N1mlF7UT9J9rdtoB5IbDBMkiccp4qib0c42BlBIP9hg/640?wx_fmt=png&from=appmsg "")  
  
写入webshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUv8jg2cibflpgKILxgb1w3Gj2n1MMucrwJZI8Kia48jA6GcBEH0tBhyrOw/640?wx_fmt=png&from=appmsg "")  
  
内网其他linux主机*40  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qicfsTOMtPEgbJ0KkJTCIwVve91eqvCUvUV5W3Ybj76tTqD0Z58P2GerHnv4vmIuGxMNa3tCqkhgk1DnpPn7ibPg/640?wx_fmt=png&from=appmsg "")  
  
总结：  
  
    后面  
跨网段然后再跨多网段  
，很枯燥的就没有往下去写了，  
内网打包直接提交上去了。  
  
