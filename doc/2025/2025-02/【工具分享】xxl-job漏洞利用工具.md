#  【工具分享】xxl-job漏洞利用工具   
孤独成诗  Sec探索者   2025-02-12 01:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkJrGicxw4mL5UYpL9RmBdKdft5iatHZicb4BrxO3ENyQOEVKKDeSwTG2Jw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "组 61 拷贝 2.png")  
  
点击下方名片，关注公众号，一起探索网络安全技术  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
      请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
**01**  
  
**工具简介**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
        工具支持检测xxl-job多种常见漏洞，并且支持多种利用方式。工具提供直观友好的图像化界面，用户能够轻松进行操作和管理。支持资产测绘、批量扫描功能，用户可以同时对多个目标进行漏洞检测，极大地提高了扫描效率。还支持暂停扫描、终止扫描、自定义多线程扫描、自定义请求头、内置随机User-Agent头、http代理、socks代理、扫描结果导出为表格等等功能。  
  
  
**02**  
  
**漏洞环境**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
工具目前支持如下漏洞的检测，我们也会持续添加poc和各种漏洞利用方式。  
```
XXL-JOB-Admin 默认登陆密码
XXL-JOB-Admin 后台RCE  ( 工具支持利用模块 :  内存马注入  )
XXL-JOB-Admin 前台api未授权 hessian2反序列化  ( 工具支持利用模块 :  命令执行 内存马注入  )
XXL-JOB-Executor Restful API 未授权访问命令执行  ( 工具支持利用模块 :  命令执行  )
XXL-JOB-Executor 默认accessToken权限绕过  ( 工具支持利用模块 :  命令执行  )
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfreib85nxF69DrIuPKjWwVWZQtY54YuqcyxXwpfcn460lQKY1A0q6p7Q/640?wx_fmt=png&from=appmsg "")  
  
工具也支持资产测绘和批量扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWft6QnuJbHtqylZCpFZZq2KicLOZtnhViaFaZ61LaaCJqSA11yFx32zxMA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfG9hzOl5gV465ZGfeia6lf3ZiaWQCPcStduae7QbibuEibibicYgBiaaDWomvQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03**  
  
**漏洞利用**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
Hessian2反序列化命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfenQNDsCxW5Ik67fqNpRibjuxLZw6vkqBFShfHwcOF1qE5U1BOLzSqKw/640?wx_fmt=png&from=appmsg "")  
  
Hessian2反序列化注入内存马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfje4qy5YPxvlEshzvypUpId9nYlbp4jHibicIMzmF5mRN7qarTknib91FA/640?wx_fmt=png&from=appmsg "")  
  
后台一键注入vagent内存马，需要再设置里面配置好Cookie （目前仅支持部分版本，且需管理端和执行端在同一台服务器）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfGCa2FS4r82chFCpeWCkKqL9PicehHTyYiac9kNDldpggDpEF8TicLgdyg/640?wx_fmt=png&from=appmsg "")  
  
目标中需要xxl-job的二级目录，注入添加的执行器和日志会进行自动删除  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfYy2DdaIibfK7QuSABS0lFK9iaTc7DpeCDw9E6IMo2SAn1TiaSu4eibBkJQ/640?wx_fmt=png&from=appmsg "")  
  
注入的内存马用的是vagent，其中  
冰蝎  
连接方式如下  
  
链接：以 /faviconb 结尾  
  
密码：自定义加解密协议  
```
private byte[] Encrypt(byte[] data) {
    byte[] dt = new byte[data.length];
    for (int i = 0; i < data.length; i++) {
        dt[i] = (byte) (data[i] + 1);
    }
    try {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        java.util.zip.GZIPOutputStream g = new java.util.zip.GZIPOutputStream(o);
        g.write(dt);
        g.close();
        byte[] c = o.toByteArray();
        byte[] ct = new byte[c.length];

        for (int i = 0; i < c.length; i++) {
            ct[i] = (byte) (c[i] + 1);
        }
        return ct;
    } catch (Exception ignored) {
    }
    return data;
}


private byte[] Decrypt(byte[] data) {
    byte[] dt = new byte[data.length];
    for (int i = 0; i < data.length; i++) {
        dt[i] = (byte) (data[i] - 1);
    }
    try {
        java.io.ByteArrayInputStream t = new java.io.ByteArrayInputStream(dt);
        java.util.zip.GZIPInputStream i = new java.util.zip.GZIPInputStream(t, dt.length);
        byte[] c = r(i);
        byte[] ct = new byte[c.length];
        for (int b = 0; b < c.length; b++) {
            ct[b] = (byte) (c[b] - 1);
        }
        return ct;
    } catch (Exception ignored) {
    }
    return data;
}
private byte[] r(java.io.InputStream i) {
    byte[] temp = new byte[1024];
    java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
    int n;
    try {
        while((n = i.read(temp)) != -1) {b.write(temp, 0, n);
                                        }} catch (Exception ignored) {
    }
    return b.toByteArray();
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWf9TmKksCwLapfKsYX6Q5mgPMoNjZahI8ZQs60MheZ27CsIanjt9XMOw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfOcrDmibwYFfP3ekicgWpWRY8KqgY6xtWB76tK0K4hYkuucezDJnEWRsw/640?wx_fmt=png&from=appmsg "")  
  
XXL-JOB-Executor 漏洞检测和利用需要在目标上Executor的端口上扫描，默认是9999，支持无回显命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzObpvibwW9bYhiblcvNaDKqWfYlxc7EjLBE1fKNKAPD5ySJCQhaYUpBKFt0UllkFlHAa5fseEeyBmew/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**工具获取**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
关注下方公众号，后台回复  
xxl-job工具  
，获取下载链接  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOIOyOhEZkrWlcianYlTNGEkfxOuWBhteCiaRdaHtePHhJMovro0Xia8kibfibrTD6TZPkMibu0pzvicIzHLg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
          
  
  
