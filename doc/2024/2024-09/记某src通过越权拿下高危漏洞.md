#  记某src通过越权拿下高危漏洞   
 船山信安   2024-09-21 08:37  
  
在挖掘某SRC时，遇到了一个社区网站，社区站点是我在挖掘SRC时比较愿意遇到的，因为它们可探索的内容是较多的，幸运地，通过两个接口构造参数可进行越权，从而获得整个网站用户的信息。  
- 图片以进行脱敏处理。  
  
- 在登录网站后，查看产生的数据包，发现了一个特定的API接口：/gateway/nuims/nuims?Action=GetUser  
  
- 通过返回包的内容判断该接口用于获取当前用户的登录信息，包括用户名（UserName）、加密后的密码（Password）、绑定的邮箱信息、绑定的电话信息以及用户的IP地址等敏感数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHAktpQPx35icBjJeiacfepgrejWourvicSGvY6VvgSTYzwLpaPgicP4d3lpw/640?wx_fmt=png&from=appmsg "")  
- 此时看到返回包的信息十分激动，这接口要是能越权，就可以看到这个站点其他用户的个人信息了，漏洞这不就来了吗。  
  
- 可回头去看请求包头，发现是get请求包，参数只有Version可以修改，但是修改后没有任何效果，尽管接口返回了敏感信息，但目前看来它并不能越权到其他用户。  
  
- 会不会存在其他的参数可以进行修改，回去翻了js文件，想查看下有没有泄露的参数信息，查看后js的一些参数并不能进行构造。  
  
- 再次查看返回包时，想到该网站会不会通过userId进行权限校验的，然后在接口构造userId进行测试。  
  
- 构造参数接口，在接口/gateway/nuims/nuims?Action=GetUser&Version=2020-06-01加上UserId参数的值，UserId参数填上其他用户即可越权查看其他用户的个人账户敏感信息。  
  
- 构造后的接口：/gateway/nuims/nuims?Action=GetUser&Version=2020-06-01&UserId=xxxxxxxxxxxxx。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHADN1qcyk0ibnhQYVQaGnDPwGphj5cIFI51puHzVdPUx6KsNwXmENUg4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHAw3IZ2tftkBBBxJxkoGSoIYeQggcPmCMibm7RKpB53icbNKiccDGXZyLgg/640?wx_fmt=png&from=appmsg "")  
- 此时我们可以看到，替换了userId参数后，可以查看到其他用户的个人信息，成功进行了越权  
  
- 继续对该站点进行测试，看看还能不能发现其他漏洞。  
  
- 通过插件findsomething获取到了另一处接口：/gw/nuims/api/v1/nuims/LcpGetUser，该接口和上一个接口返回的内容相同  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHAnhtF9kdKny1FJduFojbmV9ra6rsvvOeZxnOCt6oFDVqeC4wibvtMxNw/640?wx_fmt=png&from=appmsg "")  
- 那会不会和上一个接口存在同一个参数越权呢，继续构造参数进行测试，成功越权查看用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHArwJtibf1mplHkERdSDEc39jiclkvdcO5ctpKtzLTLL4TmDncETYnmESg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHAxcgUnUNmx17avoUDcYBLTEtYsJyYLW2l7P9J72UCCia8UYzPHwgE3xQ/640?wx_fmt=png&from=appmsg "")  
- 已经成功找到可以越权的漏洞，但是此时又出现了问题，userId参数并不是可以遍历的，不可遍历的参数，一般审核是不认可的，有可能都不给通过，更别想拿到高危了。  
  
- 所以还需要进一步挖掘，看能否获取到其他用户的userId信息，如果能拿到其他用户的userId参数，那我们不就可以拿到更多的用户信息了。  
  
- 返回首页，查看论坛界面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHAAYFAEIlAUlDWFc1nG5jWODFPX5TN5EFyJKeZJLgQdEXxo5tuViclFhw/640?wx_fmt=png&from=appmsg "")  
- 查看数据包，可以发现数据包中出现的communityUserId和之前的userId的值是一样的。  
  
- 但是communityUserId是如何获取的呢，通过点击论坛里面的帖子，可以获取不同作者的communityUserId信息，这时我们就可以获取到其他用户的userId值了，再将该值进行替换，可以越权看到他人的个人账户信息了。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHAvmOuElQJH8PQGajeHyDxmibmdfibgXR9HJFO6cX4vhUT327gsicqR1a7w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHAoFOe06zBZGibiaRK97hbBcF8mjYtibrdtHhUUxg2yuMic1VSU7sAD1cMzA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPLxKYus2CG50nfQMJHtMHA4sricJyhLCCgJWwbIXrowastF9jzEFm9IJ23ApJI8PYY0W41NicADZ1g/640?wx_fmt=png&from=appmsg "")  
- 测试完，就可以去写报告提交了，坐等高危的到来。  
  
来源：https://xz.aliyun.com/ 感谢【  
小*咔  
 】  
  
  
