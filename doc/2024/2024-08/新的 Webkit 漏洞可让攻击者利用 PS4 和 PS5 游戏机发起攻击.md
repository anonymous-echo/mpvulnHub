#  新的 Webkit 漏洞可让攻击者利用 PS4 和 PS5 游戏机发起攻击   
山卡拉  嘶吼专业版   2024-08-19 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o294FzicXqzoWufQAr0ibvB2cny6g8gx6e8MdCsXAwf9vLxt11rGIic4ichacOXIb9aNuDZexA0FoV1eRA/640?wx_fmt=jpeg&from=appmsg "")  
  
PS4和PS5中的WebKit漏洞指的是其浏览器中发现的WebKit引擎漏洞。  
  
这些漏洞在Safari和Chrome等浏览器中被发现，由于PS4和PS5共享相同的WebKit代码库，因此它们也可能存在这些漏洞。  
  
尽管单独的WebKit漏洞不足以进行越狱，但它却是关键的第一步。利用这类漏洞和内核漏洞（提供更多系统访问权限）可能会导致PS4和PS5的越狱。   
  
由于PS5具有强大的安全缓解措施，单靠PPPwn漏洞不足以进行PS5的越狱。可能需要与PPPwn结合使用的用户模式漏洞才能实现可行的PS5漏洞利用。  
  
虽然PPPwn在互联网连接期间触发，而WebKit漏洞在Web浏览器中运行，这使得按顺序利用它们变得具有挑战性。  
  
然而，WebKit漏洞对于PS5破解场景通常是积极的信号，因为它们可能为未来的漏洞利用提供途径。   
  
攻击者能够利用最近修补的Safari/WebKit漏洞，通过利用JavaScript引擎的假设，特定属性（如原型）是不可配置的。  
  
这个漏洞使它们能够被配置，从而基本上创建了类型混淆。  
  
通过操纵这一点，攻击者可以访问本应无法访问的属性，可能是通过分析阶段中使用的Spread操作码。  
  
这突显了当对数据类型的假设被打破时，意外副作用的危险性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o294FzicXqzoWufQAr0ibvB2cnUgtGiaA05AQ59RMJ4z6kq7vP8YcjIic6csFzLlLN6Sc71nE2OtGPnrbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
混淆漏洞代码片段  
  
该代码构造了一个潜在的类型混淆漏洞场景。通过从 Function 继承，Base 类获得了内置的 prototype 属性访问权限，在构造过程中将一个数字赋给 super.prototype 可能会损坏原型链。  
  
在一个不存在的 arr 变量上定义了一个 getter，以在调用 prototype getter 时操纵 victim[1]，结合一个大循环操作 victim 元素和最终的类型转换，使用可能由攻击者控制的‘flag’，创造了一个环境，在这种环境下，写入 arr[0] 可能会覆盖另一个对象的 prototype，其值为 victim[1]，从而导致意外行为的发生。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o294FzicXqzoWufQAr0ibvB2cnxnagibyfRsVzCyQ9DU6bicVrdOMG8Ir9MbylY5GHENZNtwIujk9DZia9Q/640?wx_fmt=jpeg&from=appmsg "")  
  
受此漏洞影响的固件  
  
据报道，一种潜在的影响PS4和PS5主机的WebKit漏洞已经出现。用户可以通过在主机浏览器中使用DNS重定向测试特定URL，来查看他们的设备是否容易受到影响。   
  
根据Wolo的说法，该测试利用漏洞，通过向一个恶意网页提供输入来触发“内存不足”或“系统内存不足”的错误消息，表明在PS4固件版本10.00到11.02和PS5固件版本6.00到8.60上成功利用了漏洞。   
  
参考及来源：https://gbhackers.com/webkit-exploits-ps4-ps5/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o294FzicXqzoWufQAr0ibvB2cnPfxcXv9S0a1Vvhhvp1CiamspZ1ZXb9ibmmRMpSG4Fg0GhjOMibJZTr2Pg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o294FzicXqzoWufQAr0ibvB2cnOp342zWicDQrxKhZib7GNmJA7s2kLkzexv7x3VOojSQuHaicG7z3NklSg/640?wx_fmt=png&from=appmsg "")  
  
  
