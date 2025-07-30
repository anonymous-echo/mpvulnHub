#  0day 挖到手软，403 到 getshell   
 信安404   2024-11-06 22:26  
  
开局 403  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2msvOC4yctXm8iccVlCSHUiaKCAkavWejPOcl5DNDSe1F3FXjxlN2NyYA/640?wx_fmt=png "")  
  
               
  
于是，开启目录扫描工作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt24OebmicXG2m2YLS7WCiaqAsDEHGiajiae01aeBeymWhcTnZYacMNpNyb5w/640?wx_fmt=png "")  
  
               
  
log.txt 文件泄露了日志内容，其中皆是报错信息，并且能够看到绝对路径。  
  
test.html 疑似为前台静态页面，登录时无反应。  
  
而 business 打开后会出现一个网站，在该网站上既可以登录，也能够进行注册。      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt25icAFPyqiaKf3ermfmTTzxQfudUyDGe1IAoQmkNE5LSZaJyhobT3bjwg/640?wx_fmt=png "")  
  
               
  
首先，查看登录页面，进行抓包操作，以检测是否存在注入漏洞。然而，很明显该页面不存在注入漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2owKTw3LOiab3HpWqb1brHXGVBswYsSB7m8nSsxmBdmyS3dXKElCaWkA/640?wx_fmt=png "")  
  
               
  
  
登录绕过  
  
随意输入账号和密码后，修改返回包，将原本的 “f” 改为 “t”。      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2vb3pY0AUXZicJppibnAmr2azDYfVvJz6EymM2R3E2vEoCV2dgFLWk6Nw/640?wx_fmt=png "")  
  
               
  
抱着试一试的心态进行上述操作后，没想到竟然进入了后台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt271nAoQ4ryWULRBjLvZ2sgk37oDsyVib7ASFPOxVFJQXEaynsic4NJhSQ/640?wx_fmt=png "")  
  
               
  
  
短信并发  
  
使用并发插件进行测试，原本想着会发出一堆验证码，结果却发现同一个验证码发送了两次，算是捡到了一个小漏洞。      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2x69BuG7cSVtf97yxeAAaYQ5E4MibIcoTO6P7UZyXdeGJLnpzGkwe7pg/640?wx_fmt=png "")  
  
                   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2Aic4wiaTibr1xzWjsyqnsa15zjvUAwgRU3X2UYTJpAfFwZwialeOJeqibFQ/640?wx_fmt=png "")  
  
                   
  
接着查看源代码，发现了 ueditor 的特征。通过拼接路径，成功打开了默认页面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2nql0nhPG0LSsEU7PKrq3vwl59vYh2RCia9MIFOEvKpmrReiaaCniaSd1w/640?wx_fmt=png "")  
  
               
  
进行上传图片操作时，反应十分缓慢。抓包查看后发现后端接口访问失败，导致图片无法上传。于是尝试进行 XSS测试，权当是碰运气。  
  
  
短信篡改  
  
在发送短信的时候，发现有一个 “msg” 参数，其内容虽然经过加密，但总让人感觉有些奇怪，疑似是验证码。于是选中该参数，让 Burp Suite 进行识别。果不其然，这妥妥的就是验证码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2F7F3v3JFMVQoYKat9NL6rLDcib7x6RWkPZ9QC4oP3QPYYgKibBVwzRWA/640?wx_fmt=png "")  
  
               
  
那么，是否能够改变其内容呢      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2SFXdrdGGYWFrj0Eoibd43AJODuYFHl5Dz6eCOsUsibFY9ibe5Gp8IfiaiaQ/640?wx_fmt=png "")  
  
               
  
6666666  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt294xcBsiazc8mGYcR9J6JEZkCG5VtUS1iagVz0RhXyS56ibWJvo5flsDeA/640?wx_fmt=png "")  
  
               
  
  
SQL 注入  
  
使用熊猫头，看到有很多接口地址      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2q2MakofZdXoue1hSTicNlXN4Yld6Ld8eicelQibjRLUtsU0Cr5j8EuQZg/640?wx_fmt=png "")  
  
               
  
接着进行拼接测试，大致查看一遍后发现都是查询接口，不存在删除接口。  
  
于是使用 Burp Suite 对这些接口进行测试。  
  
大部分接口都可以访问数据，但参数是空白的，要么返回 0，要么返回 1。  
  
随机选中一个，进行单引号输入测试时，出现了报错。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2sGvfoaq2ghUZ7HZ7JIUYVf99MkciasDWDX3qELy1osbuH6LtoqFMlrQ/640?wx_fmt=png "")  
  
                   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2X4XeYkIHhBrgXRNE8yAYOuhe9nEq34xbDcVWZGFMBOT3kwsPLo2XEw/640?wx_fmt=png "")  
  
               
  
直接使用 sqlmap，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2mhrtdROI4iaT69gic3Q5Q57wC0DgLPEeZHafKImH2ueSsq2H0AVVZXtw/640?wx_fmt=png "")  
  
               
  
多个接口，x 多个漏洞。  
  
  
未授权访问  
  
然后再次扫描 api 目录，发现了 swagger      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2QWjV2VpGH0t7cKicVdPa4cP7SdnVuvPopMV8wMU7VruGmSKiabr61knQ/640?wx_fmt=png "")  
  
               
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2j0tp7rltoSEV0wu3ibDcFHTWb8JJialGibMj77zgprjAdofFicDwREvibpg/640?wx_fmt=png "")  
  
               
  
其中有一个上传接口，访问 405，吆，有戏   
  
  
文件上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2icYpFHDCGiasOcr3NcgvLIibLlhQTDDPoT8oEtAahl5d6PTfLky6iccIdw/640?wx_fmt=png "")  
  
               
  
aspx 后缀未拦截  
  
一句话木马直接 getshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2z4lOAgDHfRG4gImNXL3pFSBVAclQw7O5PL8GBcHvRbyYDibow6TZNAg/640?wx_fmt=png "")  
  
               
  
最终获得以下漏洞      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt2NQiasRhrsGhg4wW1ibyXDceY7CzZlibDNS7BIdPiaEGOcUKXoDF15ic1oYA/640?wx_fmt=png "")  
  
               
  
然后看了一下供应链，才 3kw 的注册资金，没得证书，G了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZHGd0IqGcCrDK1OKCq1Nt256gfyVxH4xF315jgAu9QdBF8UEiaQ3upEfqx5sY9ibS6EVr1icGOkkOVA/640?wx_fmt=png "")  
      
  
  
  
