#  第二十课-系统学习代码审计：Java反序列化基础-fastjson反序列化漏洞原理分析fastjson利用条件分析   
原创 开发小鸡娃  安全随心录   2025-01-01 14:50  
  
**/****零**  
、写在前面**/**  
  
      
好久没更新了，后台好多私信最近都没看，有加群的和要源码的师傅的私信都没看到，以后尽力每周回复大家一次消息，入群的二维码放在了文章末尾，为了防止广告还是收费1元（只有二维码部分付费，这也是为了防止一些恶意加群的人）。代码已经重新上传到仓库了，需要源码的话群内获取。另外视频讲解地址： https://www.bilibili.com/video/BV1oFrFYMEzN/  
  
****  
**/**  
一、FastJson 介绍**/**  
  
  
FastJson 是一个由阿里巴巴开发的高性能 Java 库，主要用于在 Java 对象和 JSON 之间进行快速的序列化和反序列化。它支持将 Java 对象转化为 JSON 格式，也支持将 JSON 字符串转化为 Java 对象，广泛应用于各种 Web 框架、API 服务和数据交换场景中。  
  
  
###      
  
**1.1 FastJson 的作用**  
> 性能高效：FastJson 通过高效的算法和缓存机制，比传统的 JSON 处理库（如 Jackson）在性能上有显著的提升，尤其适用于大数据量的场景。简易使用：提供了简单的 API，使得开发者能够方便地实现对象和 JSON 的相互转化，降低了开发难度。支持多种数据结构：FastJson 不仅支持基本的 JSON 对象，还支持 JSON 数组、嵌套对象、集合类等复杂数据结构的序列化与反序列化。  
  
  
  
###      
  
**1.2 简单使用教程**  
  
```
import com.alibaba.fastjson.JSON;

public class FastJsonExample {
    public static void main(String[] args) {
        // 创建对象
        User user = new User("Alice", 25);

        // 对象转JSON
        String jsonString = JSON.toJSONString(user);
        System.out.println(jsonString);  // {"name":"Alice","age":25}

        // JSON转对象
        User parsedUser = JSON.parseObject(jsonString, User.class);
        System.out.println(parsedUser.getName());  // Alice
    }
}

class User {
    private String name;
    private int age;

    // Constructor, getters, and setters
}
```  
  
  
**/**  
二、FastJson 反序列化漏洞出现的原因**/**  
  
  
FastJson 的反序列化过程存在一定的安全隐患，主要是因为它支持通过@type 字段进行多态反序列化。这一功能虽然在处理复杂对象和嵌套结构时非常方便，但也为攻击者提供了潜在的漏洞利用点。  
###      
  
**2.1 多态反序列化（Polymorphic Deserialization）**  
  
在 FastJson 中，@type 字段用于指定具体的类类型，使得 FastJson 能够根据这个类型反序列化 JSON 字符串。如果 JSON 中包含@type 字段，FastJson 会根据该字段的值来确定实例化的类类型。然而，这一机制可能被恶意利用。  
  
###      
  
**2.2 漏洞出现的主要原因**  
> 类型白名单缺失：FastJson 默认允许反序列化所有类型的类。如果攻击者能够控制传入的 JSON 数据中的@type 字段，可能会导致不安全的类被实例化，进而执行恶意代码。反序列化时缺乏安全限制：在某些情况下，FastJson 的反序列化功能没有足够的安全检查。例如，在处理反序列化过程时，没有严格限制哪些类是允许反序列化的类，这使得攻击者可以通过构造特定的@type 字段，触发不安全的类加载。  
  
  
**/**  
三、FastJson 反序列化漏洞利用的条件**/**  
  
  
要成功利用 FastJson 的反序列化漏洞，攻击者需要满足一定的条件。漏洞的利用并不是随机发生的，而是依赖于具体的对象类型、反序列化方式以及 FastJson 配置的特性。  
  
  
###      
  
**3.1 反序列化时的那些字段可以被利用**  
  
  
**3.1.1 getter 方法调用条件**  
  
源码中执行逻辑:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9MnpyqibuMRaC7TSrlKbtQvueIUt5dOZ1RHjnMRhJQKtic9XdU0remiaNibtuiaMDHvfWudrNOGZO9MLU1YQXGLQooQ/640?wx_fmt=png&from=appmsg "")  
  
> 方法名长度大于 4非静态方法以 get 开头且第四个字母为大写无参数传入返回值类型继承自 Collection、Map、AtomicBoolean、AtomicInteger、AtomicLong 等  
  
  
**3.1.2 setter 方法调用条件**  
  
**源码中执行逻辑:**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9MnpyqibuMRaC7TSrlKbtQvueIUt5dOZ1AosfVZSCG4Y3MthxXFlOm7M8R3TAlW7E3HtRqicZgGACJOFDVjYtMEA/640?wx_fmt=png&from=appmsg "")  
  
****> 方法名长度大于 4非静态方法返回值为 void 或当前类以 set 开头且第四个字母为大写参数个数为 1 个  
  
  
  
###      
  
**3.2 类的构造函数和字段设置**  
  
在 FastJson 反序列化时，如果目标类没有 setter 方法或字段是私有的，FastJson 仍然可以通过其他机制（如  
Feature.SupportNonPublicField  
）进行赋值。因此，攻击者可以通过精心构造的 JSON 数据，利用这些特性绕过安全限制，执行恶意操作。  
  
  
###      
  
**3.3 防御措施**  
  
为了避免 FastJson 反序列化漏洞的发生，建议开发者在使用 FastJson 时遵循以下几点：  
> 使用白名单限制类类型：明确指定哪些类可以进行反序列化，避免恶意类被实例化。避免使用不安全的反序列化方法：尽量避免使用 FastJson 的parseObject方法，改用更加安全的方式进行 JSON 的解析。加强 getter/setter 方法的安全性：确保目标类中不包含不必要的 getter/setter 方法，尤其是那些可能被恶意利用的。  
  
  
  
