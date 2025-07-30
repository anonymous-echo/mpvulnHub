#  java审计之下载漏洞获取到的代码如何断点调试  
 进击的HACK   2025-06-12 23:51  
  
前言  
  
文件下载漏洞获取到网站源码，想通过代码审计漏洞，但是逻辑太复杂，难以直接复现出来，这时候就需要断点调试了。  
  
  
演示  
  
以调试jar包举例，这里以之前下载到的源码演示一下  
```
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar web.jar
```  
  
出现5005表示运行成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjlFaogJzd1d1XMNTMQntpu7TmauZ8fp9aXyhGLUIOEyHic3icLnlRR4lQ/640?wx_fmt=png&from=appmsg "")  
  
1、在线平台  
  
https://www.decompiler.com/  
  
这种方法比较简单，将代码放到在线平台反编译，这个平台反编译后的代码比较完整，方便调试。在线平台可能会存在泄露代码的问题，安全起见可以使用本地工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjhChcQRu987mlnS1avgLoBOHIXOTzzldbkmSLKeh6Dp47icqchx8bvKA/640?wx_fmt=png&from=appmsg "")  
  
将反编译后的代码打开，编辑配置，选择远程调试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjc2yNwAnG0LIVESAvrSzBiazlmHEvBJWdvlcIRheXyPs8bhbYSBDspaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjmKxlQs34uoPtz4az3QnQDpel6AFPnWqKtWSGNusEtzOsn3M3VOLwog/640?wx_fmt=png&from=appmsg "")  
  
点击确认，最好项目的jdk版本与本地运行jar的版本相同  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjXibNdLgvlN2wsKZPhsMPXFfhflSia9rp29a74lksojklrXgKn3JSzoyA/640?wx_fmt=png&from=appmsg "")  
  
点击调试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjvKRWHib1SY5T1t1TWgYFnxlslrO3QCdsS6jeWmoVndvlNGHXFj8Zayw/640?wx_fmt=png&from=appmsg "")  
  
连接成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjld30GQLUqDQhPEAE1ia2xGpTsTx6rnb6eU6uP66icuoMAMyNO5p6y0qA/640?wx_fmt=png&from=appmsg "")  
  
然后打开本地运行的jar服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjicK8KPoPIDRfB4Fn9db1NE1mrFf4mKCALRicuqhGicMXib3cDv5MCrBicYQ/640?wx_fmt=png&from=appmsg "")  
  
对登录接口断点一下试试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjXqJibIeZksjT74AaOhpIsLibjBHOoZwxfzDHFAbiacC9YvAldD3Jx9qJQ/640?wx_fmt=png&from=appmsg "")  
  
成功将数据断下来  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjc0HaB6W6xRB6jYZx3O1c1u8ibLUZdSlht6H8PwLHrUQVibYkZvOavZdA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjFkKibCsjUNJnWsDnvg1yxXqak6Y4ZmQFicia6iahaTNwj9IICZjuicjDBqw/640?wx_fmt=png&from=appmsg "")  
  
接下来就可以  
像有源码的程序一样正常调试了  
  
2、本地工具  
  
如果不想使用在线平台，可以使用本地工具  
  
将jar包直接解压代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZj8RiauYWaNKibqsT0ftsSUqCuRlHVcjJLvEAicKjgS04svg1o5QBEo4PjQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjagMws9g42nK0S3NDEGJIiahD1qbnn7dfQuNRmkwnQ7V2yJMlkLrmKZQ/640?wx_fmt=png&from=appmsg "")  
  
  
IDEA新建一个空项目，  
项目结构->库，选择刚才解压程序Jar包中  
的BOOT-INF/classes  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjc3weh24ko4faSNFS2CJe0Keatciavr2iaabpyCH8NJ7O4I7LsJ2D7caA/640?wx_fmt=png&from=appmsg "")  
  
模块处勾选刚才导入的依赖  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjkoPMyQglUF94roCScfWiciasgtDwJHajOAQ4L2pcROLiaP3z7xv8hKNzQ/640?wx_fmt=png&from=appmsg "")  
  
添加完毕后，在左侧依赖库侧边栏中显示了这个依赖  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjuUXhs9HcAHjqgJibqAolUorm4YUwIJwY9ookzU8WR8gEEtm0lclrwTw/640?wx_fmt=png&from=appmsg "")  
  
再将刚才解压  
ja  
r包中  
的BOOT-INF/lib添加进依赖里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjIaM2ppw29sjlo5T35cOfQszvPP2tbGRZMZDWoKibqlPUt2gBrotCibibA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZj76oYnLxBzG4JZjgIFabwe7qZWJa0VKibZPzl0dc6Y0XKBv1Ng5mTpvg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjLLfiaAHnK17cxFZyxSldsIlA6qTtFqZThKcc9apwrTiakIY1gKY3ibM0g/640?wx_fmt=png&from=appmsg "")  
  
找到登录接口代码进行断点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjx9LBS3mAKZEyWtG12RGZnKicWWYHXPPepDL7u5iave0pqCfhxEIHxVnA/640?wx_fmt=png&from=appmsg "")  
  
和刚才一样配置远程调试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjvdTNr4bz5dZLUKQpGsCqfY67UhIVGob51m7SGibP2xwxx3cswibGj9SQ/640?wx_fmt=png&from=appmsg "")  
  
点击登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjibSwVeIAm1CxMykECOQLuG7Aic3KJibydy7dAtjRHccF1tiaYwmMuBjndA/640?wx_fmt=png&from=appmsg "")  
  
成功断点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjuMyDrwrzqicLf1CRWibDCOL65dNySkibMqEibJqy8j6icicS9Tn9ibOAt0j7w/640?wx_fmt=png&from=appmsg "")  
  
补充：  
  
如果我想修改jar包的代码后再调试呢？  
  
idea下载插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjmyZk6kxtQdTlGT5uq1rcAfKlF0jtt4Kn5JAyqmoWq5wqpCluyT2WAw/640?wx_fmt=png&from=appmsg "")  
  
然后使  
用maven，  
将本地的 JAR 文件手动安装到本地 Maven 仓库中  
```
mvn install:install-file -Dfile=E:\xxx\xxxx\xxxx.jar -DgroupId=com.test666 -DartifactId=house -Dversion=0.0.1 -Dpackaging=jar
```  
  
E:\xxx\xxxx\xxxx.jar为你要修改的jar包位置，  
-DgroupId    -DartifactId可以随便写。  
  
记住这个路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjCm9GzLQ0UTKjmFRC637zvtDc3Zo9tvZEibBk9lVuy18yhNQmostr7UA/640?wx_fmt=png&from=appmsg "")  
  
新建一个空项目  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjVMTTVXoF229BwTujoLFnFXibEGJBdbcm2UzlTO1yLZu9LkibXyISRnmQ/640?wx_fmt=png&from=appmsg "")  
  
在的pom.xml中导入刚才安装到本地maven仓库的项目  
```
<dependencies>
    <dependency>
        <groupId>com.test666</groupId>
        <artifactId>house</artifactId>
        <version>0.0.1</version>
    </dependency>
</dependencies>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjdINrlOPedv9xSXxRYPykezsY7dWG1qpHO3ZIP9zBerlQicpGuy8l5lA/640?wx_fmt=png&from=appmsg "")  
  
同时IDEA设置中maven仓库位置要选对  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjMLtJEzvIw4vxH2BRR09DpZRmTa9vxySJce1kfFUINPIY2ryyqsq0eQ/640?wx_fmt=png&from=appmsg "")  
  
左侧依赖库可以看到刚才导入的依赖  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjX8HichdaDbr5Unf5C4VgdYCLmUjng3SBicicHUUCd7ibZfibQHcwrUrDIzg/640?wx_fmt=png&from=appmsg "")  
  
找到要修改的代码，这里我随便修改了信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjfD3HU5HxCYeWR0WObqRQic4GmUQzia0ibDBrvlicVCXywYlmmDlDR4AlTw/640?wx_fmt=png&from=appmsg "")  
  
修改后使用插件保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjKBhPIIUsoja7xKsuw41ia2wxA5wpiabgVoXiaj2KpfA7nOYiaydXQdqONw/640?wx_fmt=png&from=appmsg "")  
  
来到刚才的maven仓库位置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjdUKVh3XAYMibBlmVOibR5sEphD5VEVKnqAa2ulFtaNhvRRNlZHwUeYdA/640?wx_fmt=png&from=appmsg "")  
  
重新修改后的jar包位置在这里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjtSPN2RhRnwFNzwdcmqXB112FwVElLexYapXKcFGFNKCz5OLzpO1TMg/640?wx_fmt=png&from=appmsg "")  
  
运行jar包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZj1km6zMIKLTMribyXpOWdqQCcI6r86Jk5pq66OTMibGS6oia0ibGkbuGpicA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjN7fWcrnic5XL7SlYY4y0kVtzicmURx3ib0VpC2EeXNVXU2GsYIta4zG0Q/640?wx_fmt=png&from=appmsg "")  
  
  
代码成功被修改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib8tyK0eV6CBVZ2gOveAajZjKvSysPjibwAIsQo2VCeOqAeiciab9dcicbLsibus5Ttmn5QO3u1Iz9RjrNw/640?wx_fmt=png&from=appmsg "")  
  
  
