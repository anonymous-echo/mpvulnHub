#  EMQX命令执行后渗透   
 Khan安全团队   2025-05-28 00:32  
  
欢迎转发，请勿抄袭  
  
        上一期说到EMQX后台插件命令执行，但是这个命令执行结果是无法回显示，那么如何通过暴露的mqtt服务进行利用呢？命令执行容易，后利用很难(出网情况就不用折腾了)。  
  
        mqtt是一种轻量级的消息协议，专门用于在低带宽、不可靠网络或双方之间需要进行简单通信的场景下传输消息。用于物联网设备之间通讯。采用发布主题和订阅主题方式通讯。  
  
利用方式一：  
  
        使用mqtt协议将命令执行结果通过发布主题形式回显。使用python编写一个mqtt程序，采集执行的结果发布。同时订阅收到的命令执行。编译好的可执行文件，通过插件的方式上传并执行。将执行文件放到my_emqx_plugin/src  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VL5iamcicAsOibD4icEJAlDSqZpZiaL2qH3XySY9iaKK7eJJULrru9IS0hfvg/640?wx_fmt=png "")  
  
并添加以下命令在命令执行处添加执行的命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VwtwKia7TlggbBp4kKSKVVRWNNFCnpXM8Qqr1fbs1IuXU2fQ4IZSPBGQ/640?wx_fmt=png "")  
  
回到emqx后台管理，将刚编译好的插件上传执行，多数会提示失败（因为执行到rce那一步，会卡住下面的执行）但是目标程序已经运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VQV0Sf0NvR3UEnSUPo8zGsBbx1mC5vHC9Vl1dfcuZXPskHgSYkZSEVQ/640?wx_fmt=png "")  
  
执行完后，在主页看到上线情况。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VYy3NxYUPY4uVib0PnTfZYYxZ1pox3Pt4H7zT1bBtiaXyJg9WX60t1UKw/640?wx_fmt=png "")  
  
可通过mqttx客户端进行连接对客户端进行操控利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VSmib9o0w1QQr4exCSl5I2wialBfS2MuLX12gzxuI75GgKrzBibLibFLahw/640?wx_fmt=png "")  
  
rce执行程序发布一个tx/test主题，订阅rx/test主题。mqttx则要相反，订阅tx/test主题，发布rx/test主题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6V7kqVRJTlJm11OtfAH6TbBEIwdeib2jcMkHhZcghGWKwhibdGhUe88GPA/640?wx_fmt=png "")  
  
到这一步已经实现了通过mqtt协议将命令执行结果回显。如果卸载不了插件，使用mqtt里面的命令执行起一个rce，再关掉插件起的rce，就可以卸载插件了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6V4HYjRWgfbedbJ1vibdYhxxhRDOUra3zNcphLXKkhTa2Qz5ChtBnf4Aw/640?wx_fmt=png "")  
  
利用方式二：  
  
        使用mqtt协议特性通过发布主题形式传输数据，达到内网穿透。我这里使用一个http代理去修改，因为http也是一个请求返回一个响应。服务端httpserver->httpserver-mqtt,客户端httpclient->httpclient-mqtt。流程图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VxZ52PrarRs16KK6gYDicARte8yClj0eSmg6jbxhc7S96S1RiaM2rSjCA/640?wx_fmt=png "")  
  
编译好可执行文件，将httpserver和httpserver-mqtt通过插件方式上传到目标机器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6Vk0b3YBYtMUgmd1mW3sEoy2zcIibsCicbqBOPibtToSjnCzs0tyoiboLPVQ/640?wx_fmt=png "")  
  
使用  
利用方式一中的命令执行功能，将可执行文件执行。  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VbJUbcS04pZagwfo9pnj0dWs8lztwfuSvJFnw3yjWnaGQgicg5fOYHow/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VCnwhBFpMOU3ezxdHSVDcYsJcqDzrKnVcYSAjzQs4icLUMK5gJb2ibmPQ/640?wx_fmt=png "")  
  
此时还没运行可以看到只有两个连接，添加一个1.sh的文件。目的是为了两个可执行文件同时执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VVugibyJCh7bbIltwkcMyPHWJtFpWmXV2ekWzmDh01CHibCUv6rUGic7Zw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VcvH95KT6KfdIglbQYj81t8oNvrYAQdLSjN1kDliawFFtlo9yf9NJNxg/640?wx_fmt=png "")  
  
执行1.sh后，会将server和servertomqtt的两个个可执行文件执行。通过面板发现已经成功运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6V6Op3aibeSjcqF4W6Ik8N9XRJ3UvK8LUBB9oIogSLNEZgLLMmVMQ6Low/640?wx_fmt=png "")  
  
使用连接客户端进行连接访问隧道。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VK7Cq9LCiaoIL5xbTHZtqDHPT9T9M7LfRiaia2phw003z4FOvLIhLnZy8g/640?wx_fmt=png "")  
  
成功通过隧道代理访问里面内部资源,默认172.17.0.1为宿主机器ip。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6V6LrjYB2DRJN8wibWcCVZSH5iaVicI9JuW5nhjA3dYIeaWjKwO2zGKkpaQ/640?wx_fmt=png "")  
  
mqtt数据流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VBDANT4SDNAJJBtKUibOD4bvvUKYNESDF18OOn5bDQgDlRde62zojh1A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXl7f9oWdNJUW9sVlPPkkS6VoUyn1dib0zravC54BK1OwPQiaDDzZ3Dpf37NHK013Nt1g2KXuuTM5oRw/640?wx_fmt=png "")  
  
  
文章声明：该工具、教程仅供学习参考，请勿非法使用。否则与作者无关！  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
