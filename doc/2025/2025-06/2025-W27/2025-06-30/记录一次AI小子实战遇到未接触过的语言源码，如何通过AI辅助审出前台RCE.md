> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4MzkwNzI1OQ==&mid=2247486750&idx=1&sn=3edb517ea02d8bd6dc95a9caf128d84c

#  记录一次AI小子实战遇到未接触过的语言源码，如何通过AI辅助审出前台RCE  
原创 C@ig0  菜狗安全   2025-06-30 01:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThblPVAndvyTpQFwq1A0r1dWhvB7eMS9aib6BWewwHCOepINib6su4KMIibw/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
  
由于传播、利用本公众号  
菜狗安全  
所提供的信息而造成的任何直接或者间接的后果及损失，均由  
使用者本人负责，公众号  
菜狗安全  
及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，会立即删除并致歉。  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
  

```
前言
坐牢打点遇源码泄露
AI出手激情审计
失败的SQL注入
前台文件上传黑名单
突破WAF限制GETSHELL
最后 
```

  
  
2sdfs  
  
# 前言记录一次AI小子实战遇到未接触过的语言源码，如何通过AI辅助审出前台RCE坐牢打点遇源码泄露AWVS，Nessus，dirsearch... 启动！启动！通通启动！好吧一个有用的都没有，这时候AWVS发力扫到个dv*****.zip，100+MB，难道说？火速下载到本地好消息：是源码泄露坏消息：是.NET的，我不会AI出手激情审计但是这能难的住我AI小子吗？失败的SQL注入通过翻文件看到疑似SQL查询的代码  
  
AI一通分析下来，简单来说就是10-14行通过POST接收参数，这里会经过GetInputReplce()方法，16行判断  
bitSpace  
是否为空值，为空则赋值为1，18行  
当用户ID (
```
intMemberSrl
```

  
) 非空且不为 
```
0
```

  
，且 
```
staff
```

  
 为 
```
&#34;0&#34;
```

  
（非员工）时，执行查询，这几个值都可控无所谓，20行拼接
```
intMemberSrl
```

  
 方法进入DBCON.EXECUTE(),执行sql语句，  

```
GetInputReplce方法定义，通过头部文件包含，找到对应方法文件
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPmmXMzCfjGKcXYKxsNvfXwQn3Gia8Nic1cXE6aDKzJPUZc3HUm9cAB0iaicPKXqjLTibouvTMRvxXibXeiag/640?wx_fmt=png&from=appmsg "")  
  

```
先判断传入的strValue是否为空值，不为空进入if，使用GetReplaceInjection方法进行处理，搜索方法
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPmmXMzCfjGKcXYKxsNvfXwQEdibVNBQdbxicsMic0ic237KiaAg1jm5fLSIMj6EFYLnfTFPSHLia0BsmjEw/640?wx_fmt=png&from=appmsg "")  
  
过滤主要采用替换的方式，AI分析后发现是单次循环过滤，select之类的字符可以通过双写绕过，'替换成'',项目数据库采用SQL Server，不能通过\'绕过，''在  
SQL Server是转义',这里貌似没找到解决办法，其实还可以找有没有查询接口没有调用  

```
GetInputReplce方法的，但是发现项目有容错处理，错误回显报错页面，注入最多也是盲注，考虑到网络连通性+WAF就没有接着搞下去了
```

  
  

```
前台文件上传黑名单
```

  
  
通过翻看文件名发现一个  
file.upload.asp，看路径和文件内容发现是前台能触发的，继续Ai启动  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPmmXMzCfjGKcXYKxsNvfXwQvOL1EPPzEdJjqYicY3Ko8YIJ5HLYxw7edGPdY1bt9spmgSsFbBJt6yw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPmmXMzCfjGKcXYKxsNvfXwQvR3HoQ4753wWw7tB3wLbS12shrxO7c405mzzxicIDBM9dLSs3iaHGx7w/640?wx_fmt=png&from=appmsg "")  
  
处理上传逻辑的方法是ActFileUpload，通过同步包含文件找到对应方法  

```
    ' 定义文件上传处理函数，接收上传组件、文件字段、上传大小限制、保存路径等参数
FUNCTION ActFileUpload(uploadComponet, strFileField, intUploadSize, strPath, bitThrum, strThrumOption, bitUseWaterMark, strWaterMarkOption)


    ' 声明局部变量用于存储文件信息和处理逻辑
    DIM nowFileSize, nowFileName, FileExe, strSaveFIleName, strFileNameOnly, I, strUploadNotFileTmp


    ' 获取上传文件的大小和原始文件名
    nowFileSize = GetUploadFileInfo(uploadComponet, strFileField, &#34;size&#34;)
    nowFileName = GetUploadFileInfo(uploadComponet, strFileField, &#34;name&#34;)


    ' 如果文件名为空或为 NULL，则返回 False 并退出函数
    IF nowFileName = &#34;&#34; OR ISNULL(nowFileName) = True THEN
        ActFileUpload = False
        EXIT FUNCTION
    END IF


    ' 如果文件大小超过指定限制，则返回 False 并退出函数
    IF INT(nowFileSize) > INT(intUploadSize) THEN
        ActFileUpload = False
        EXIT FUNCTION
    END IF


    ' 生成不重复的文件名（防止覆盖已有文件）
    strSaveFileName = GetChgSameFile(strPath, nowFileName)


    ' 提取文件扩展名并去除多余的点
    FileExe         = REPLACE(MID(strSaveFileName, INSTRREV(strSaveFileName, &#34;.&#34;) + 1), &#34;.&#34;, &#34;&#34;)


    ' 提取不带扩展名的文件名，并去掉单引号
    strFileNameOnly = REPLACE(LEFT(strSaveFileName, INSTRREV(strSaveFileName, &#34;.&#34;) - 1), &#34;'&#34;, &#34;&#34;)


    ' 文件名长度超过60字符时截断
    IF LEN(strFileNameOnly) > 60 THEN strFileNameOnly = LEFT(strFileNameOnly, 60)


    ' 定义不允许上传的文件类型列表
    DIM strUploadNotFile
    strUploadNotFile = SPLIT(&#34;php,php3,php4,ph,phtml,asp,js,css,jsp,pl,c,cpp,stb,shtml,shtm,vbs,htm,html&#34;, &#34;,&#34;)


    ' 遍历不允许上传的文件类型，若匹配则将文件重命名为 .txt 格式以确保安全
    FOR I = 0 TO UBOUND(strUploadNotFile)
        IF TRIM(strUploadNotFile(I)) <> &#34;&#34; THEN
            IF UCASE(FileExe) = UCASE(strUploadNotFile(I)) THEN
                IF UCASE(strUploadNotFile(I)) = UCASE(FileExe) THEN
                    strSaveFIleName = strFileNameOnly & &#34;.txt&#34;
                    EXIT FOR
                END IF
            END IF 
        END IF
    NEXT


    ' 调用函数创建目标路径的文件夹（如果不存在）
    CALL ActFolderMake(strPath)


    ' 替换单引号为下划线，避免路径错误
    strSaveFIleName = REPLACE(strSaveFIleName, &#34;'&#34;, &#34;_&#34;)


    ' 根据上传组件类型选择不同的方式保存文件
    SELECT CASE LCASE(uploadComponet)
    CASE &#34;abc&#34; : strFileField.SAVE strPath & REPLACE(strSaveFIleName, &#34;;&#34;, &#34;&#34;)
    CASE &#34;dext&#34; : strFileField.saveAS strPath & REPLACE(strSaveFIleName, &#34;;&#34;, &#34;&#34;)
    CASE &#34;tabs&#34; : strFileField.SAVEAS strPath & REPLACE(strSaveFIleName, &#34;;&#34;, &#34;&#34;)
    END SELECT


    ' 判断文件类型是否为图片格式，如果是则根据参数进行缩略图生成和水印添加
    SELECT CASE UCASE(FileExe)
    CASE &#34;JPG&#34;, &#34;GIF&#34;, &#34;BMP&#34;, &#34;PNG&#34;, &#34;TIF&#34;


        ' 若启用缩略图功能，则调用图像缩略图处理函数
        IF bitThrum = True THEN CALL ActThrumImage(strSaveFIleName, strPath, strThrumOption)


        ' 若启用水印且使用 dext 组件，则调用添加水印函数
        IF bitUseWaterMark = True AND uploadComponet = &#34;dext&#34; THEN CALL ActDextWaterMark(strSaveFIleName, strPath, strWaterMarkOption)


    END SELECT


    ' 函数返回最终保存的文件名
    ActFileUpload = strSaveFIleName
```

  
那么简单来说过滤就一个，黑名单后缀，关于可执行文件只过滤  
asp，看似好像有很多后缀可以上传，但是多数后缀文件上传服务器会解析错误，返回error页面，发现项目中有aspx文件，尝试上传WAF拦截。。。  
  
突破WAF限制GETSHELL  
  
通过测试可以上传  
Ashx，但是访问爆error，通过报错信息判断文件是存在的，大概了是解析文件问题，这就很尴尬了，能上传的不解析，能解析的waf拦，等等好像忘记了什么？AI启动！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPmmXMzCfjGKcXYKxsNvfXwQMH18u2JSrQYKktyZZmDtj9iajFCjvibM2acz504bkc7vSMOu1AeH3hEg/640?wx_fmt=png&from=appmsg "")  
  
最终在一系列的解决方案中，发现可以使用  
Unicode 编码绕过waf，并且文件可以正常访问解析  
  
使用AI分析代码生成对应上传数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPmmXMzCfjGKcXYKxsNvfXwQMTPuibBviapd7kjZGSn0eRxsnB9eGH33JI6QJiaCuMibNYubl0wZcWTpvg/640?wx_fmt=png&from=appmsg "")  
  
上传文件名为 xxx.as%70x，成功突破WAF文件上传，访问文件成功代码执行  
  
  
后续其它事就和我个AI小子没关系了，接着打点坐牢。。。  
  
最后  
  
实际上文章内容省去了很多步骤，很多图片和细节是不能发的，这个源码还是花了点时间的，因为完全没接触过，WAF绕过不过的时候有很多奇思妙想，但是都被环境一一否绝了，拿到的是备份源码，实际上生产环境会和源码有些许差异，比如上传后保存的文件名实际上是原始文件名，而且有目录穿越，考虑过覆盖.cs文件，然后访问对应编译文件的aspx文件，加载恶意C，一大堆稀奇古怪的想法，但是WAF和生产环境给了我当头一棒，还有文件保存路径是多个文件方法拼接的也花了点时间定位，还好最后是GetShell了不枉那些时间。  
  
