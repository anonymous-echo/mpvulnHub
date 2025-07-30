#  API安全漏洞靶场crapi漏洞复现   
 进击的HACK   2024-12-04 23:55  
  
#   
# 项目介绍  
  
crAPI 应用程序被建模为 B2C 应用程序，允许任何用户让汽车修理工完成他们的汽车维修。用户可以在 WebApp 上创建帐户、管理他/她的汽车、搜索汽车修理工、提交任何汽车的服务请求以及从供应商处购买汽车配件。WebApp 还有一个社区部分，用户可以在其中贡献博客文章和评论。  
  
crAPI 应用程序在设计上并未以最安全的方式实现其所有功能。换句话说，它故意暴露安全漏洞，任何使用该应用程序的安全爱好者都可以利用这些漏洞。有关漏洞的更多详细信息，请参阅  
challenges.md  
  
crAPI 具有微服务架构，包括使用不同技术开发的以下服务：  
  
web: 主 Ingress 服务  
  
身份：用户和身份验证端点  
  
社区：社区博客和评论端点  
  
车间：车辆车间端点  
  
mailhog：邮件服务  
  
mongo：NoSQL 数据库  
  
postgres：SQL 数据库  
# 安装  
  
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml  
  
docker-compose pull  
  
docker-compose -f docker-compose.yml --compatibility up -d  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaJ25UCic7fLpnF9BuZt7gibYYD1c6iauISicXMC2RVGDribetYezia83Blbcw/640?wx_fmt=png "")  
  
常见问题排除  
  
https://github.com/OWASP/crAPI/blob/main/docs/troubleshooting.md  
  
由于该项目更新比较快建议使用纯净系统安装  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWalZkSjbbblMNqFsU05s6XdwP9NT9b57ePYGWPZwdsDZlBt4vdyK5TPA/640?wx_fmt=png "")  
  
host绑定解析域名 ，通过域名访问该站点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWahFfcsryfSRJCDnFce2bZBPjJqaL2Gn7xicnPEWmMR1jCVSX6h9ia5syA/640?wx_fmt=png "")  
  
  
#   
# 失效的访问控制  
  
挑战1和挑战2都是失效的访问控制导致存在的越权问题，通过GUID或者其他端点获取其他用户的信息以及凭证，因此在我们做测试时需要一个初始访问权限，注册一个账号。test@qq.com/test123@  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaDdleT3YU2dzPjsoZWZTsrcZdHggRmtMZiad6Mwmmn1ZghTpbWYtqfOA/640?wx_fmt=png "")  
  
  
通过前端获取大量隐藏接口信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaICcJoDoDJw1tCr7KfOvaqlyrnb694g06JnLTAYNVW9bU3zunlpJ2FQ/640?wx_fmt=png "")  
  
   
# LAB1- 访问其他用户车辆的详细信息  
  
挑战描述：  
  
要解决这个挑战，您需要泄露其他用户车辆的敏感信息。   
由于车辆   
ID 不是序列号，而是 GUID，因此您需要找到一种方法来公开其他用户的车辆 ID。查找接收车辆 ID 并返回相关信息的 API 端点。  
  
首先我们需要添加一个车辆信息来获取关于车辆相关的参数，8025端口是一个简单的邮箱系统，当我们注册用户后会给我们发送车辆信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaHG85icIiawloSWibt1dLbz0gyjPwQFdVALMmdA9S5XJIRCAzRedKFibWCA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWauCJV4edtSbdyyW0UichZFQFQShqZ67AOibAIdBrzQ69agDdTePsxYzQw/640?wx_fmt=png "")  
  
  
通过获取的车辆添加一个车辆  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaGuaD00IjEVCfPJ93BibKjLIC4hTOgVNL7UeVEkbxQMCasKB8uIn2kicA/640?wx_fmt=png "")  
  
然后在   
JS代码中查找相关接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWa7ibNCXftXCElrq2ibzETt0avTxxjykYicnRoCPc24KYiaHRWkUJicrnOsBQ/640?wx_fmt=png "")  
  
  
根据梳理发现关于车辆报告相关的接口有4个，一个添加订单、一个订单信息、一个发送确认订单信息  
  
ADD_VEHICLE:"api/v2/vehicle/add_vehicle",  
  
GET_VEHICLES:"api/v2/vehicle/vehicles",  
  
RESEND_MAIL:"api/v2/vehicle/resend_email",  
  
REFRESH_LOCATION:"api/v2/vehicle//location",  
  
  
   
搜索:REFRESH_LOCATION接口调用方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaOibjicLqPYqD07bgT8xCAU7VlF6aF3D0dzK6aT7wkiaF0EJQ51lTAH5JA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaurXHlwIaEMbuaPS1Q2VpoB4gc1GuFOo4zbnxKnIhayuBJIgjJbkAcg/640?wx_fmt=png "")  
  
  
越权查看到车辆的ID  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaX8ffqS4nFFATWD9O0ItAjPaMKUU4caaazSZPBSHLqdDTyDetjsf2kQ/640?wx_fmt=png "")  
  
# LAB2-访问其他用户的机械报告  
  
挑战描述：  
  
crAPI 允许车主通过提交“联系机械师”表格来联系他们的机械师。这个挑战是关于访问其他用户提交的技工报告。  
  
分析报告提交流程，找到一个隐藏的   
API 端点，该端点公开了机械报告的详细信息，更改报告 ID 以访问其他报告  
  
添加一个机械报告  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWazrN79evRUaUFJoIkzu30TOmAKw0TiaYMVTr0rd8ky5fR0qhvatQClEQ/640?wx_fmt=png "")  
  
   
  
当我们添加一个报告后发现返回了一个报告连接   
http://www.crapi.com:8888/workshop/api/mechanic/mechanic_report?report_id=6  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaMHyQck5hbQIucs5ibOT1GFiapMyhjqS2oF5ZNfibStCrVtEQ9Ugve2uqA/640?wx_fmt=png "")  
  
通过访问该ID连接可以发现那个用户提交的报告  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWau0mibKrI3kNs3xGo9VdhmWHjrwQUXP0ZMes6dUrkicIjEta7DAMot5wg/640?wx_fmt=png "")  
  
修改该ID参数即刻获取其他用户的报告信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaEfUWEpXQoPwezKOibPthu9jBS0fT0XeFWjwkciaPlFVsjzkIhdHCfLiaw/640?wx_fmt=png "")  
# 损坏的用户身份验证  
## LAB3 - 重置不同用户的密码  
  
挑战描述：  
  
在 crAPI 上查找另一个用户的电子邮件地址 暴力破解可能是答案。如果您面临任何保护机制，请记住利用 REST API 的可预测性来查找更多相似的 API 端点。  
  
重置在crAPI 上获取到的用户邮箱地址：robot001@example.com  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWayXiaujraBVIiaTWroTd0Qygb4IzQrVhpSvW8GmPC3zFB1HXtibguyqO4A/640?wx_fmt=png "")  
  
在邮箱服务中发现该验证码为四位验证码，可进行爆破测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWalWyTwTRs7uiaLVia6BibxTRs1qTYHIM0DciaAdEYpVJFnNTKfKERSVNPaw/640?wx_fmt=png "")  
  
通过枚举该参数可以直接爆破成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaibDOfPCc9jbGzDglDPcv23hTf9I01lEdicOL0VIq1icOiaXzcyf6sAqNvg/640?wx_fmt=png "")  
  
然后发现使用v3端点存在防爆破机制  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWasiby06kXNwicRMmyl6g00VZCWYIAfVibxYPZR4Agia6yAXqaia2vEJ5Ekgw/640?wx_fmt=png "")  
  
使用v2端点则可以绕过防爆破机制实现密码重置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaMCenGnov5cUicAWia5dV0LLstMSbjIoaNnwbHAibnh6GttPGcLHo2xPqA/640?wx_fmt=png "")  
  
下图为爆破成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaOK4zauAhpBkkxuS2s825ribHxeF6dwdmMbsqsc1A5eDm9VR9rIkMARw/640?wx_fmt=png "")  
  
# 过多的数据暴露  
## LAB4 - 找到泄露其他用户敏感信息的 API 端点  
  
通过在评论页面的返回包中发现大量用户敏感信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaV40NhPQ3iaRbhSuuONuMrLk0ZFlPPyLxMBZVtyusgJeXRuDMR82JnUA/640?wx_fmt=png "")  
  
API端点:/community/api/v2/community/posts/recent  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaHHcQdzuEqUBpTuKVf8IG87hUNzlTeSKMM3sStnCiabT36M0B3f0HAGQ/640?wx_fmt=png "")  
  
**LAB5 - 找到泄漏视频内部属性的 API 端点**  
  
挑战描述：  
  
在此挑战中，您需要找到不应向用户公开的视频资源的内部属性。此属性名称和值可以帮助您利用其他漏洞。  
  
在个人信息中可以上传视频信息，上传视频测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWajFNg58yUqibJlb72qnpaPvNcjHia1NXJqI2wQACfg4C5ykbtxtuA6yTw/640?wx_fmt=png "")  
  
通过抓包发现上传视频为identity/api/v2/user/videos 端口，通过抓包看到视频信息以ID作为参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaNNfyicicdzZxtOjhlBH4qxFlKsyvO4POWZZrsDcZasx5yfoEsZXcFFiaA/640?wx_fmt=png "")  
  
结合之前获取的所有接口信息，发现使用videos端点有3个，  
  
UPLOAD_VIDEO:"api/v2/user/videos",  
  
CHANGE_VIDEO_NAME:"api/v2/user/videos/",  
  
CONVERT_VIDEO:"api/v2/user/videos/convert_video",  
  
   
如果我们需要越权查看到别人的信息，通过api/v2/user/videos/端点实现越权测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWazAnvkAhyZTRVicVO2PjKgyWnibu0d1s7OzHwz6Fbz06tplMT5VRcYJBQ/640?wx_fmt=png "")  
  
通过修改文档名发现api/v2/user/videos/端点修改其他信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaubZ3aFYicTunibmb2L1JPw3alfKic6fL9fmfYPcuHE13yDwNpVs1GlNicw/640?wx_fmt=png "")  
  
# 速率限制  
## LAB6 - 使用“接触机制”功能执行第 7 层 DoS  
  
API通常不会对客户端/用户可以请求的资源的大小或数量施加任何限制。这不仅会影响API服务器的性能，导致拒绝服务，而且还会为暴力破解等身份验证缺陷敞开大门。漏洞可能导致DoS，造成API无响应或不可用。  
  
Challenge 6 - Perform a layer 7 DoS using ‘contact mechanic’ featureS  
  
第   
7 层是指互联网的 7 层 OSI 模型的顶层，也称为“应用程序层”。这是数据处理的顶层，位于用户与之交互的软件应用程序的表面之下或幕后。例如，用于加载网页的 HTTP 请求和响应是第 7 层事件。在这一层面上发生的 DDoS 攻击称为第 7 层攻击或应用程序层攻击。  
  
分布式拒绝服务（DDoS）攻击是通过大规模互联网流量淹没目标服务器或其周边基础设施，以破坏目标服务器、服务或网络正常流量的恶意行为。  
  
DDoS 攻击利用多台受损计算机系统作为攻击流量来源以达到攻击效果。利用的机器可以包括计算机，也可以包括其他联网资源（如 IoT 设备）。  
  
总之就是短时间通过大量的请求访问占用服务器的资源从而导致服务器不能对正常的流量做出响应。  
  
找到api将repeat_request_if_failed改成ture，将number_of_repeats改成一个很大的数字，重放测试实现DDoS攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaqxGIiajjLzoTN52ozfDwChkz8HwTZwYAxbF8T4pic8J2OnokTiafvEB6g/640?wx_fmt=png "")  
  
**LAB7 - 删除其他用户的视频**  
  
挑战描述：  
  
利用   
REST API 的可预测性来查找管理端点以删除视频 删除别人的视频  
  
/identity/api/v2/user/videos/31端点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaQtNE6NLIUBgIaXV8jJpRDbiaBStERPClnztjiaiaPYNR5nGk4MLs1QGZw/640?wx_fmt=png "")  
  
使用OPTIONS协议探测支持的http协议  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaibTzibdTJq2hsRkN7v8IreOTQjuic4mliccA5cZRt9LXQNZ96YTAUtGp1Q/640?wx_fmt=png "")  
  
  
使用DELETE协议删除该视频,提示需要使用管理员端点才能访问，将user改为admin即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaqO4MAgzvSt1cqJZAgFxko7Yrek0eehsbGOUhwPYia2Krrx2zibicmrH0Q/640?wx_fmt=png "")  
  
DELETE /identity/api/v2/admin/videos/31  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWarpAyNel7ice4ZC3vK2QOBOX8Iu1lhHLxMVYRsPFGIeLfyzCDMRib2ULg/640?wx_fmt=png "")  
# 批量分配  
## LAB8 - 免费获得一件物品  
  
挑战描述：  
  
crAPI 允许用户退回他们订购的商品。您只需单击“退货订单”按钮，收到二维码并在 USPS 商店出示即可。要解决这个难题，您需要找到一种方法来获得您实际上并未退回的商品的退款。利用 REST API 的可预测性来查找允许您编辑特定订单属性的影子 API 端点。  
  
使用PUT协议进行报错发现订单的多种状态'delivered'(已交付),return pending(订单处理)'or 'returned(已退货)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaNibeEQJduibrGfvYtDbztvoEfNI9oNiblDBziamyTWECLTSmYQssvibR7cA/640?wx_fmt=png "")  
  
通过设置退货的状态信息为returned已退货。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWah484AWxRW6iauuk1vAdP00vlfyXodvMj80rS23fDMPJVM8Iic5H1KmMw/640?wx_fmt=png "")  
  
通过设置订单退货状态来获取商店的赔付金钱，实现免费获取商品。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWalsM9rmgicAgKUNUb2RV0vcJ2uyQyDEPCoopRARCobvbmg3zf74Ytmicg/640?wx_fmt=png "")  
  
  
**LAB9 - 将余额增加 1,000 美元或更多**  
  
挑战描述：  
  
解决“免费获得一件物品”挑战后，发挥创意，找到一种方法让您从未退回的物品获得退款，但这次尝试获得更大的退款。  
  
通过添加数量实现将产品的金额提高  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWae6XIbrVVnMWOTNdVZsZwSPg0quevysqO1O7A9mZibmjuPlOiaf5bvWcw/640?wx_fmt=png "")  
  
然后在使用退款的形式获取更多的余额  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaicLEVpJF80ymTiba8cTbvbQU1DKv6GQ7CGJ0ay3P16gtVMwChhtlY3nw/640?wx_fmt=png "")  
  
获取产品接口，尝试使用POST协议添加产品  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaNibyR5Ofnbb2ic5ZP9bI9x9nRLo9WLYwQvncehoib59BbnVo5OfHMfpEg/640?wx_fmt=png "")  
  
通过设置负数商品来获取购买过程中的逻辑赔付功能   
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWalTjaUwtwzyq8cgbGdibXF1fWEuVn9tBZtNLODJJdM1nfiaCY0hK45icww/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaIw5bIp1iaTDMGiaQ45YGyNq0E10HfjbMcicsFbKux8zXibXS7lou4jouJw/640?wx_fmt=png "")  
  
由于是负值所有在购买产品时他会返回金额给我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWa7a5RsJlLLE2SjR89N8XZ3R3fVFLMam9rPU9zATfhAM0qo1Rrhdt3xg/640?wx_fmt=png "")  
  
**LAB10 - 更新内部视频属性**  
  
挑战描述：  
  
在解决“查找泄漏视频内部属性的 API 端点”挑战后，尝试找到一个允许您更改视频内部属性的端点。更改该值可以帮助您利用另一个漏洞。  
  
由于该API端点目前存在问题导致无法更新其他人的视频属性。  
  
SSRF  
  
LAB11 - 让 crAPI 向“ www.google.com”发送 HTTP 调用并返回 HTTP 响应。  
  
在维修申请时会发送一个远端的URL请求，从而请求发送到远端服务器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWa7Ub1IQZh52tfGlicMcBgvvRwllEMchvH8iaibtMYLVOo1hGg80owy7GTg/640?wx_fmt=png "")  
  
通过抓包修改mechanic_api参数实现对远端请求服务的控制，从而实现SSRF漏洞，发送带外的DNSlog请求。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWa18bvQ0HtoCpyt8JaWosTIGnSRHH8PllbyMOO4s6KmgwfBIFVAEG63Q/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWa2SiaxfxfJtK2ibNfhcRSPOvH3ouN4Opa0ZIxIo3O7lic61ZZiaqD24hHjA/640?wx_fmt=png "")  
# NoSQL注入  
## LAB12 - 想办法在不知道优惠券代码的情况下获得免费优惠券。  
  
通过提示该题为Nosql注入,NoSQL 注入由于 NoSQL 本身的特性和传统的 SQL 注入有所区别。使用传统的SQL注入，攻击者利用不安全的用户输入来修改或替换应用程序发送到数据库引擎的 SQL 查询语句（或其他SQL语句）。  
  
换句话说，SQL 注入使攻击者可以在数据库中 SQL 执行命令。  
  
与关系数据库不同，NoSQL 数据库不使用通用查询语言。NoSQL 查询语法是特定于产品的，查询是使用应用程序的编程语言编写的：PHP，JavaScript，Python，Java 等。这意味着成功的注入使攻击者不仅可以在数据库中执行命令，而且可以在应用程序本身中执行命令，这可能更加危险。  
  
在兑换优惠券功能我们可以看到该功能为一个查询，对于关系型注入的话可能代码就是: or 1=1#实现查询为真的结果。但是该处为NoSQL注入，我们可以通过FUZZ   
SQL语句的方式获取查询语句。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaNxaIO4VMicx1g4Niapkwm5Rtv5rHwFPnH5xYNnYqRTuIjsMznIz06icnA/640?wx_fmt=png "")  
  
通过枚举模块设置FUZZ SQL查询语句，注意该处我列举了Nosql常用payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaRTTEtNPzovvgjWTYGM7U8pgMcQYAicgku0v5ax5OAcgeppL10Yibjukw/640?wx_fmt=png "")  
  
通过枚举发现{“$ne”:-1}参数绕过查询，成功获取到兑换码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaDuabO46NBAjwa5fqia3wFVuoc4ibiaPYICB4tAicxjkhX8PEBkZiaG6fjxQ/640?wx_fmt=png "")  
  
  
通过输入正确的对话码，实现优惠券兑换成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaYk6ZjYpbKKqndISqhmpLeIHGSvQ5bA0d1AY9VHde9qc3u30rRBQnuA/640?wx_fmt=png "")  
  
参考：  
https://www.jiangguo.net/c/kVz/EDy.html  
# SQL注入  
## LAB13 - 找到一种方法来兑换您已经通过修改数据库领取的优惠券  
  
该题提示为SQL注入，找到存在SQL注入的端点，通过FUZZ   
SQL语句的形式，获取到SQL注入语句"1'0r1'='1"。  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWarsJsrhG3x0CDPxWCb7WRud1rVaazPGhUACpjOnCtVSTWVryjgrfm2g/640?wx_fmt=png "")  
  
这个端点上存在SQL注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWa7uk7VdKpO4A1MghuJMZAxxGRibUJcGmvTONX9L0y29xhicIaZu42No0w/640?wx_fmt=png "")  
  
**LAB14 - 找到一个不为用户执行身份验证检查的端点。**  
  
该题为未授权访问漏洞，通过删除header头处的Authorization认证信息来获取存在未授权访问的端点，在这里我用的时burp的Authz插件检测是否存在未授权访问的端点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaJQcdZ7NFiajCnRbXGG1s6RV5rLKh8IZ4vib4Mk3pyQUxia2KJqictEuI6A/640?wx_fmt=png "")  
  
该端点无需用户身份权限直接获取用户订单信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWasuYvsNsL4mFzvgnFNloD7k4pAT6rtgckicqDzG1QpIbISXTYsPx8j2Q/640?wx_fmt=png "")  
# JWT 漏洞  
## LAB15 - 找到一种方法来伪造有效的 JWT 令牌  
  
挑战描述:  
  
crAPI 中的 JWT 身份验证容易受到各种攻击。找到任何一种方法来伪造有效的 JWT 令牌并获得对平台的完全访问权限。  
  
通过对JWT_token的解码发现该站点使用RS256算法，该题为算法混淆攻击  
  
如果将算法RS256修改为HS256（非对称密码算法=>对称密码算法），则库的通用verify()方法会将公钥视为 HMAC 机密，公钥有时可以被攻击者获取到，所以攻击者可以修改header中算法为HS256，然后使用RSA公钥对数据进行签名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaIjlkX8QDiagXPiaQ8yD5smXwmWwwwNp1MVm6w8Faj7WZXXbsgyEQzOgg/640?wx_fmt=png "")  
  
  
   
localhost:8888/.well-known/jwks.json 获取jwt的公钥  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaItHw0liaEvvSnfO96DJrVGUmHlZtPZrMKW9FLvZ12taDrNBJZDvetow/640?wx_fmt=png "")  
  
去到JWT editor选项卡，点击New RSA Key 复制JWK set内容 保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaKveErVBGticmEqhXgeQIACklMl5kj8lARKHjzpic0aucuicaZ9WCPKE9Q/640?wx_fmt=png "")  
  
  
   
之  
后再右键我们新建的Key Copy Public Key as Pem  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWacNpGNIbqDVgcrJBQRA2czVvrqHfiaGibKjgOJdJavgHKtx78iaTglDUgg/640?wx_fmt=png "")  
  
去Decoder选项卡对这个 PEM 密钥进行 Base64 编码，然后复制生成的字符串  
  
再次回到Burp 主选项卡栏中 的JWT Editor Keys选项卡，点击New Symmetric Key Generate  
  
将   
k 属性的生成值替换为PEM Base64编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaSKETwFygHkoYWOCPx8WTemna9LDCUW0vHeB8F6oR0hpYMrsdwkvsBg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWazwLmvj01xW6h3nDcrFB5jk4gHlXiaibLGdhUJC3jUOqcZJbstwCxP0Kw/640?wx_fmt=png "")  
  
然后在burp的请求中可以发现json  
   
web  
   
token选项卡  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaZEjH58Un0vEfTmJibVVcicfaVyFraWvBAIJ5xliatSDbXribTwChJ1n8Vw/640?wx_fmt=png "")  
  
  
通过调用该选项卡实现对json   
web   
token的各种工具，例如修改header头信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaKmMH02hZndPLIyVPMgZDSnUsFTsR0DyWcAunLFKBvPDFamo5PRZLdQ/640?wx_fmt=png "")  
  
在选择卡左下角处也可以看到对json  
   
web  
   
token的攻击选项。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibQxG9cezyUawyz1ia0uk2NFBiaU9icMeCWaO1Zqft3p9KQO8sKrlUAEJvMPcaRwCXrGdia9xH8Be5Ot7sAuOhFiamrg/640?wx_fmt=png "")  
  
  
参考：   
https://github.com/OWASP/crAPI/blob/ff8ee954ddc0eb12990474e0662a21e1c0a8c63a/docs/challengeSolutions.md  
  
https://blog.csdn.net/weixin_63231007/article/details/127748765  
  
https://xz.aliyun.com/t/11904#toc-7  
  
  
