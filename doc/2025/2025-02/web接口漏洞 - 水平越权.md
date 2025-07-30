#  web接口漏洞 - 水平越权   
原创 xiaoliao1  信安一把索   2025-02-10 10:21  
  
一  
、漏洞介绍：  
  
水平越权访问是一种“基于数据的访问控制”设计缺陷引起的漏洞。由于服务器端在接收到请求数据进行操作时没有判断数据的所属人/所属部门而导致的越权数据访问漏洞，而这种越权最容易出现的位置就是？Id=（传参值） 和 post 传参的参数中，或者存在个人信息页面，个人资料这些隐藏的接口中  
  
二、漏洞原理  
  
水平越权漏洞的原理在于，当Web应用程序接收到用户请求时，如果没有对用户的权限进行严格的校验，就可能允许用户执行超出其权限范围的操作。例如，一个用户A通常只能对自己的信息进行增删改查，但如果后台在处理这些操作时没有判断所操作的信息是否属于该用户，就可能允许用户A操作用户B的信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SYFH3GGyDoogQ4iafMtd1DbB2QWjzIX7xY1UeHQ3iavU8DTRnPGGHovsERcKibF7nyib06fKK8iaR7PxRVKYhO4Q1Rw/640?wx_fmt=png&from=appmsg "")  
  
三、漏洞利用  
  
方法一：  
  
往往在挖掘过程程中，拿到同一个站点，别人能挖掘出水平越权或者垂直越权，而你却不能发现，那是因为这些越权漏洞的传参值都是接口在进行，所以我们在挖掘的过程中可以打开 burp 抓住每一个包，然后再去看 burp 中的 http 历史记录，查看接口信息，在进行测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SYFH3GGyDoogQ4iafMtd1DbB2QWjzIX7xPso4NSk1rCPIsfUu7WExUPlSdcch3xibTWNy2FjsFwPluLhGODc20aA/640?wx_fmt=png&from=appmsg "")  
  
如果在站点页面是无法看见?sid 这个参数的，而你在 burp 历史包中即可以看见此参数，这个参数就是个人身份的参数，如果没鉴权，那么水平越权就到手。  
  
方法二：  
  
  
直接使用浏览器的控制台中的网络即可查找，比如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SYFH3GGyDoogQ4iafMtd1DbB2QWjzIX7xdvZU0zyXf7Y8IcfIkSsdTR1d561Yndg650tsfibCGXgN9vfriafpIfDA/640?wx_fmt=png&from=appmsg "")  
  
可以看出这个页面，你根本没有任何办法测试水平越权，但是你可以通过查看接口的办法将个人信息的接口查找出来后进行测试：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SYFH3GGyDoogQ4iafMtd1DbB2QWjzIX7xjNhDgr5yewWJ0riaD2qnoOOmibj0ZX93WgdujeQFibS5PqGwA4J3cM8pQ/640?wx_fmt=png&from=appmsg "")  
  
调用后，你可以将参数？abllid=参数值换为别人的参数，即可测试是否存在越权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SYFH3GGyDoogQ4iafMtd1DbB2QWjzIX7xddibeWO4XvMhTlRp08HciaeGRdKq8wKl0uxt81v1kO3XS1tmLKhHHricg/640?wx_fmt=png&from=appmsg "")  
  
