#  Android Intent 重定向漏洞分析总结   
NEURON  SAINTSEC   2025-02-01 02:02  
  
‍  
  
‍![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpbDmiaT8r2hsTTCjAP6fYbmN09lZqJVk69yHzPVupa2E5dJ5rZgblg8pg/640?wx_fmt=png "")  
  
  
  
前段时间发现2021ByteCTF的几个Android题，和APP漏洞相关的，对此很感兴趣，所以做了一些学习总结。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpbDmiaT8r2hsTTCjAP6fYbmN09lZqJVk69yHzPVupa2E5dJ5rZgblg8pg/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepoYDmNTEC8QO2xDT001YNW0eKNtV8y9lb0PqkphqjDf8icbNJzw06DuUas5OR8z7xo/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWeplibVFyhQcBHibTdX7ONIjz2uTQb7VB4TIIPTTYrCXyfJ0NB44hN6wFV5iaJGibsBjgNG/640?wx_fmt=svg "")  
  
intent 介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepHyn3W1Mk9icK4Pr8fCoS9bL0sMHruyvj99EjUe5EFh2ibT0ZFBVQAHK6UOSu3TiaxjH/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepRfMy6YVhqveVE7LBjiaV9KgfiaiaWhIRrpX71q6RC64dj4MtMhZ4tbTqQwKuVTsLVsQ/640?wx_fmt=svg "")  
  
  
  
Intent（意图）主要是解决  
  
Android  
  
  
  
应用的各项组件之间的  
  
通讯  
  
  
  
。例如：  
```
```  
  
Intent负责对应用中一次操作的动作、动作涉及的数据、附加数据进行描述，Android则根据此Intent的描述，负责找到对应的组件，将 Intent传递给被调用的组件，并完成组件的调用。  
  
Intent对象中可以包括这些信息：  
  
1. 组件名称(Component): 指定Intent的的目标组件的类名称。  
  
2. 动作(Action): 将要执行的动作  
  
3. 种类(Category): 被执行动作的附加信息  
  
4. data (数据) : 表示执行动作要操纵的数据。  
  
5. type (数据类型) : 显式指定Intent的数据类型（MIME）。  
  
6. extras (扩展信息) : 是其它所有扩展信息的集合。  
  
7. Flags (标志位) : 期望这个意图的运行模式。  
  
Intent的两种调用方式：  
- 显示调用  
  
对于明确指出了目标组件名称的Intent，我们称之为显式Intent。  
  
```
```  
  
	  
我们写代码来理解一下，可以发现使用了setComponent，putExtra等来添加Intent对象中的信息：  
```
```  
  
	  
当点击跳转后，页面进行跳转，并且数据传输成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpboFeeW5hmLw8H3bttkp22t57CasCIGVEpGAeUfepRQib6CBLHcbsiciccQ/640?wx_fmt=png "")  
- 隐式调用  
  
对于没有明确指出目标组件名称的Intent，则称之为隐式Intent。  
  
隐式调用需要通过Intent Filter来匹配对应的组件。  
```
```  
  
点击跳转按钮，达到和上图同样的效果，这就是显示调用和隐式调用。  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepoYDmNTEC8QO2xDT001YNW0eKNtV8y9lb0PqkphqjDf8icbNJzw06DuUas5OR8z7xo/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWeplibVFyhQcBHibTdX7ONIjz2uTQb7VB4TIIPTTYrCXyfJ0NB44hN6wFV5iaJGibsBjgNG/640?wx_fmt=svg "")  
  
intent 重定向  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepHyn3W1Mk9icK4Pr8fCoS9bL0sMHruyvj99EjUe5EFh2ibT0ZFBVQAHK6UOSu3TiaxjH/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepRfMy6YVhqveVE7LBjiaV9KgfiaiaWhIRrpX71q6RC64dj4MtMhZ4tbTqQwKuVTsLVsQ/640?wx_fmt=svg "")  
  
  
  
  
        简单介绍了Intent之后，我们来了解一下什么是重定向，其实它就是一个双层嵌套，根据下图理解，攻击Apk使用startActivity(intent1)进入受害apk的Activity1，Activity1中会接收一个intent(称intent2，这个intent2指向攻击Apk中的Activity2)类型的数据，对这个intent2使用startActivity(intent2)，这样最终就进入了Activity2。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpbR2F8SoibcMyTmlouJaglr2jgwdS8GrFlygPvjzehTDqIjdrSic2UKiaibQ/640?wx_fmt=png "")  
  
接下来我们编写代码来进行实际演示，这里注意Activity1和Activity2都是导出的，也就是exported="true"，否则会失败。  
  
攻击APK关键代码：  
```
```  
  
受害APK关键代码：  
```
```  
  
整个过程如下图，实际看到的是，点击按钮后直接跳转到”重定向成功“界面，但中间会有一个空白界面就是我们的Activity1：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpbDGsWZf6Wwm14QIwqCfyFjduQQ8nnShFxrohyRhFWnUWo7SxjU7HQFg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepoYDmNTEC8QO2xDT001YNW0eKNtV8y9lb0PqkphqjDf8icbNJzw06DuUas5OR8z7xo/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWeplibVFyhQcBHibTdX7ONIjz2uTQb7VB4TIIPTTYrCXyfJ0NB44hN6wFV5iaJGibsBjgNG/640?wx_fmt=svg "")  
  
ByteCTF 2021-babydroid  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepHyn3W1Mk9icK4Pr8fCoS9bL0sMHruyvj99EjUe5EFh2ibT0ZFBVQAHK6UOSu3TiaxjH/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepRfMy6YVhqveVE7LBjiaV9KgfiaiaWhIRrpX71q6RC64dj4MtMhZ4tbTqQwKuVTsLVsQ/640?wx_fmt=svg "")  
  
  
  
        本文是根据ByteCTF 2021的Android题来进行学习，在之前我们了解了Intent重定向，但是这往往需要和其他利用条件结合，也要保证要攻击的Activity是导出的，而这个题就可以帮助我们巩固知识。  
## 分析APK  
  
JEB反编译，查看AndroidManifest.xml文件，发现Vulnerable是可导出的，可能漏洞点就在这里。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpb3dkiapo7ugiayKUeicLBpBybFzQGSnSdPIHibWm7X5114eYl9JZGWN8Obw/640?wx_fmt=png "")  
  
        MainActivity是空的，没什么用，FlagReciver是一个广播接收器，经分析是设置flag的，将接收的flag写入文件，这应该和做题的人关系不大。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpbmF0I5PLOZa6PcoPdibuWJ36BDr2vRJzVOs9CcYFjIHKiazVVrvP07HKA/640?wx_fmt=png "")  
  
        但是这里有一点要注意，getFilesDir()是哪个目录呢，这里可以自己写代码进行验证，给一个参考图，来自：  
https://bbs.pediy.com/thread-271122.htm  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpbUINLnqrjq8Wk42eKzb8gT3nnCsUh8fbJFT9tMpZtCPn8Ms8uvvadcA/640?wx_fmt=png "")  
  
        所以这里flag文件存储的目录是/data/data/com.bytectf.babydroid/files/flag。  
  
再查看Vulnerable类，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpb4Clib0bibrj1VqJicicAw3ctaF8YOjFm2SbUbuZcmCGykrwNCBW9XK8Zrg/640?wx_fmt=png "")  
  
        这个类导出，而且接收一个Intent数据，所以我们可以利用Intent重定向漏洞。  
  
        那我们该怎么利用Intent重定向漏洞读取flag文件呢？  
  
## FileProvider  
  
	  
 Android 7开始不允许以 file:// 的方式通过 Intent 在两个 App 之间分享文件，而是通过 FileProvider 生成 content://Uri 。如果在 Android 7以上的版本继续使用 file:// 的方式分享文件，则系统会直接抛出异常。  
  
	  
 FileProvider 是一个特殊的 ContentProvider 子类，如果使用包含 Content URI 的 Intent 共享文件时，需要申请临时的读写权限，这可以通过 Intent.setFlags() 方法实现。  
  
	  
我们在AndroidManifest.xml中也看到了FileProvider，  
```
```  
  
	  
文件配置完成后还需要生成可以被其他 App 访问的 Content URI，可以直接调用 FileProvider 提供的 getUriForFile(File file) 方法，，传入文件名称就可以得到相应的 Content URI。  
  
	  
 假如我们要获取flag文件，但是我们也不确定Content URI是多少，我们编写代码来得到结果，看看Content URI生成的格式：  
```
```  
  
	  
这样我们就得到了我们攻击时应该使用的Content URI格式。  
## 攻击  
  
	  
了解了前面的知识，我们该做最后一步，对apk实施攻击获取flag。我们使用Intent重定向将Content Uri在受害Apk中进行解析获取flag文件的数据，在攻击APK中接收flag，完成攻击。  
  
首先使用命令发送广播，创建flag文件：  
```
```  
  
然后编写攻击代码：  
```
```  
  
攻击结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBAROkop6B2zOjRibPOSzpbEo480CCQfoIRGFY88OSTcMzpB2BltXDYUBPibQLZnoGFxKLe8rI0tSw/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepoYDmNTEC8QO2xDT001YNW0eKNtV8y9lb0PqkphqjDf8icbNJzw06DuUas5OR8z7xo/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWeplibVFyhQcBHibTdX7ONIjz2uTQb7VB4TIIPTTYrCXyfJ0NB44hN6wFV5iaJGibsBjgNG/640?wx_fmt=svg "")  
  
总结  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepHyn3W1Mk9icK4Pr8fCoS9bL0sMHruyvj99EjUe5EFh2ibT0ZFBVQAHK6UOSu3TiaxjH/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/8h9QXaJ70ibe4kYbwic4qdx33ovyricFWepRfMy6YVhqveVE7LBjiaV9KgfiaiaWhIRrpX71q6RC64dj4MtMhZ4tbTqQwKuVTsLVsQ/640?wx_fmt=svg "")  
  
  
  
	  
这个APK出现漏洞主要是因为Vulnerable类导出，虽然FileProvider是不导出的，但是通过Intent重定向可以在受害APK内部去使用FileProvider，因此达成了利用条件。一直以来，我主要是做APK逆向，而对于APK的漏洞确了解的很少，而且也很难有漏洞去复现学习，还是很感谢ByteCTF的出题师傅，之后应该也会对其他题目进行复现学习，再和大家分享学习。  
  
  
  
‍  
  
‍  
  
