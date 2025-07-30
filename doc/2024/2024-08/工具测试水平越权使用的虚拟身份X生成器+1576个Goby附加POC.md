#  工具|测试水平越权使用的虚拟身份X生成器+1576个Goby附加POC   
原创 老呆  卫界安全-阿呆攻防   2024-08-24 11:54  
  
此文章只为学习而生，请勿干违法违禁之事，本公众号只在技术的学习上做以分享，知识生产需要时间，最近也没什么发的，呆哥在做公司儿童医院测试要用身份证注册，非得要16岁以下的，自己瞎编注册的一直报错不行，所以找到个宝藏项目打包了一下，简单对代码进行分析一下完全OK，有兴趣的自己优化，呆哥怕存在法律风险，且觉得没必要花时间搞，就单纯推荐一下项目，然后最后贴一个Goby的附加POC下载路径，  
所有行为与本公众号无关。  

				
				  
  
   
  
01  
  
项目介绍  
  

				
				  
  
- **项目名称**：idgen  
  
- **项目地址**：https://github.com/mritd/idgen  
  
- **项目描述**：一个使用 golang 编写的大陆身份X生成器  
  
   
  
02  
  
项目详情  
  

				
				  
  
有三种模式：  
  
1. **命令行模式**：直接命令行运行二进制文件即可生成对应信息，生成后将自动复制到系统剪切板  
```
➜  ~ idgen --help

This tool is used to generate Chinese name、ID number、bank card number、
mobile phone number、address and Email; automatically generate corresponding
text to the system clipboard after generation, and generate ID number by
default without sub-command

Usage:
  idgen [flags]
  idgen [command]

Available Commands:
  addr        Generate address information
  all         Generate all information
  bank        Generate bank card number
  email       Generate email address
  help        Help about any command
  idno        Generate ID number
  mobile      Generate mobile phone number
  name        Generate name
  server      Run as http server
  version     Print version

Flags:
  -h, --help      help for idgen
  -v, --version   Print version

Use "idgen [command] --help" for more information about a command.
```  
  
2. **服务器模式**：使用 server 子命令将启动一个带有页面的 http 服务器用于浏览器访问， 同时还会启动一个 json api 接口用于其他程序调用  
```
➜  ~ idgen server --help

Run a simple http server to provide page access and json data return.
When the -m option is not specified, both html and json support are enabled,
and the access address is as follows:

http://BINDADDR:PORT/        return a simple html page
http://BINDADDR:PORT/api     return json format data

Usage:
  idgen server [flags]

Flags:
  -h, --help            help for server
  -l, --listen string   http listen address (default "0.0.0.0")
  -m, --mode string     server mode(html/json)
  -p, --port int        http listen port (default 8080)

Global Flags:
  -v, --version   Print version
```  
  
3. **Docker模式**：Docker用户直接运行   
docker run -d -p 8080:8080 mritd/idgen 即可  
  
这里我就展示一下Windows的情况（因为Github上release没有打包，我这打包好放网盘自取）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyYltbl9IrmL3Bx8LXwnc1PwXCkkEIG6WiauU3MmBnumZJV0Q9HCV6pFA/640?wx_fmt=png&from=appmsg&random=0.3512810760932794&random=0.12518884517576812&random=0.6707595401769264 "")  
  
▲ 命令行模式  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyGCSY7m8KxRyBPvkVqfWWjh2p9VkCCUSmln5rgtQKLzXdLJ8VY4G6hg/640?wx_fmt=png&from=appmsg&random=0.8366563076421547&random=0.7016761602774408&random=0.4946326157260341 "")  
  
▲ Server模式命令  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyWbmmtdpmJxkZdCRicibIqSRZWfHpy7ZleDHxg2OtD4R5hbRP4AKj8s1g/640?wx_fmt=png&from=appmsg&random=0.8273652028527074&random=0.9477713559972609&random=0.05214593946560808 "")  
  
  
  
▲ Server模式  
  
   
  
  
03  
  
浅析代码  
  

				
				  
  
分析项目  
idgen的源码看看有没后门，代码量不大，看了一下这个项目就是一个纯cmd的调用+http的服务器构建。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqybw3DTWJYvdClGnB3hnC5aAyktvhOGPlpuQXlf5xCMBoLgbB1tbtgQQ/640?wx_fmt=png&from=appmsg&random=0.5346863017789147&random=0.6237680820452998 "")  
  
main调用的cmd中的Execute函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyRmibgxWpKMkxs1GDtOwMF6f0Q1UjpOsjEOOtoNicoRmDibsDHsRYbnTIQ/640?wx_fmt=png&from=appmsg&random=0.3555089390184212&random=0.16320356502876798 "")  
  
点开发现都是调用，实际来自于该作者另一个项目：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyMXN2nadJvGDwU2roibU70lNhvGs5JJhOjAcIxacBuy8HQp8a39b1Rlg/640?wx_fmt=png&from=appmsg&random=0.6169101363305647&random=0.7530329780100364 "")  
```
https://github.com/mritd/chinaid
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqytoRAqGtGeSicvQLYE6wyz2uENZYnWvfVxRxh5vQUBnBgiadozoZDV8Ow/640?wx_fmt=png&from=appmsg&random=0.722399293445473&random=0.8594769486365639 "")  
  
这里面才是实际的生成逻辑，都很简单，但是根据一定的生成规则，metadata中是他的数据元数组，举例一个card_bins：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyuMO8YU8qcehAtOtrMxRuZlH5zfEdRibBprfbLdH3pLAC4GiaNIibUHxkA/640?wx_fmt=png&from=appmsg&random=0.7934102928812128&random=0.5010342134694661 "")  
  
看完后没有后门，我就编译了一个。  
   
  
04  
  
Goby附加POC  
  

				
				  
  
 导入完成后：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyAic9bjsriaAdEyY0GreIdmO49iaqOpVGzbIPSenDicibNKmL7KGrhcJDzKQ/640?wx_fmt=png&from=appmsg&random=0.890924658784372 "")  
  
   
  
05  
  
网盘位置  
  

				
				  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsVaCSzzCvODYOYnvUsH2tUIaLQUsMCzS0cVediaNlV0Mukr7oJKPDdqEm1H8yD8syBmiav7CqTIVhA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&random=0.9441560173420269&random=0.9689460117070476&random=0.11983567427755037&tp=webp "")  
  
  
资源共享->网盘分享  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqy5zNbItaAKMIdHC6pE0HwK67Z6bqQ2ZEqXcRH5zmgbjnXMxqEWKmL7g/640?wx_fmt=png&from=appmsg "")  
  
渗透->goby补充POC  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMtBwGI1k2pXrM6VAS6XdQqyWJst7wffazcd7aShIH1m8VFEgib2njqiazgk1LYYD3rIeMt7iauPiavhzw/640?wx_fmt=png&from=appmsg "")  
  
渗透->虚拟身份X生成器  
  
