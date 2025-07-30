#  SRC实战案例分享-验证码漏洞   
原创 隐雾安全  隐雾安全   2025-05-20 01:00  
  
1  
  
**验证码爆破导致任意密码重置**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZUHXib55oQ6GrAEwe1FYUYH58Be0erZZoDPhn53mdUa5wzbqHLEdGRzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
点击获取验证码后 随便输入一个 进行抓包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZE4yrhDZibw7ic99ibvibgxp36Z1SCKwx61OtPWl37iayPbiaLDicKTmMibggVg/640?wx_fmt=png&from=appmsg "")  
  
  
将验证码设置为变量 进行爆破  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZovE6c74icsLib0y5Mf0bD37dFoc1OtYeiaBkOXDp6nthPEjqPcOC7ibWJQ/640?wx_fmt=png&from=appmsg "")  
  
  
失败返回  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZUbRyhzVWRZSiamWglqGGvLcKHJVRYtjDSccE6c2IcITajLKJbMO5Yog/640?wx_fmt=png&from=appmsg "")  
  
  
成功返回  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZXo5EibuADC7xzfegh4esicgaJkEq9iaaDabBuESicxgeD26iaTdJ1YzicibIw/640?wx_fmt=png&from=appmsg "")  
  
  
这里我分了10个线程进行爆破成功爆破出了验证码  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZaRYoRbcrcJwZ64pIIyjurELzoDHIzgdLt3RibJ19dNs0XXKWv3icwiahA/640?wx_fmt=png&from=appmsg "")  
  
  
结果比对  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZow64rwDtv22la2ulehibshweJsRhJGXxicnxUvkHQn5mrQtq6RFu9PCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**2**  
  
**验证码回显导致任意用户登陆**  
  
  
通过抓包 来查看回显包的得到验证码来任意用户登录。  
  
输入手机号点击抓包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZ81Jdgu9l10JpNk9lSEBBMPmNmXscHpIribjYUpqja9drkHlEAcRGmibg/640?wx_fmt=png&from=appmsg "")  
  
  
进行发送  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZ6KtViaVy6iaEQE1gHwOQicSmCDuQFwbPVZ8UpIFQmj0iafSEicukQqk3BYg/640?wx_fmt=png&from=appmsg "")  
  
  
结果验证  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZNXvwTfETBHJURHqIYHLqwEVgrGHeXes2SeyON8cTT6Cfk5ZP5ibYE4w/640?wx_fmt=jpeg&from=appmsg "")  
  
**No.3**  
  
**网安沟通交流群**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ELQKhUzr34zyVNSmLNLliceLgryyV3mNZ0EgL2krjdO0LIDpnCeWvfK1vsNb7uCbY5vhhroHx3Aw3ia7oygdyeLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**扫码加客服小姐姐拉群**  
  
  
  
