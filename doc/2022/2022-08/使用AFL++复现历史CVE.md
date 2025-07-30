#  使用AFL++复现历史CVE   
Azyka  看雪学苑   2022-08-12 19:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8HTChwTbPQDUrl0FibBt2pZYv9MWsxqPDRltOtQmZYVhPzrmenS5VPGrVvNroiaQuwQk8ic1lZLvfQPA/640?wx_fmt=jpeg "")  
  
本文为看雪论坛优秀文章  
  
看雪论坛作者ID：Azyka  
#   
  
这是我做Fuzzing101的一些笔记，通过复现CVE的方式熟悉AFL++的基本使用方式，过程对我这样的萌新十分友好，同时中间涉及到的代码审计等方面还是值得后续学习的。  
  
# Exercise 1 - Xpdf  
  
  
CVE-2019-13288（  
https://www.cvedetails.com/cve/CVE-2019-13288/  
） in XPDF 3.02 （infinite recursion）  
##   
## 安装调试目标  
  
  
从github等途径下载并解压。  
```
wget https://dl.xpdfreader.com/old/xpdf-3.02.tar.gz
tar -xvzf xpdf-3.02.tar.gz
```  
  
  
安装依赖和目标。  
```
sudo apt update && sudo apt install -y build-essential gcc
./configure --prefix="$HOME/fuzz_target/fuzzing_xpdf/install/"
make
make install
```  
  
  
配置configure时有各种环境变量需要设置，比较常用的有：  
- AS：汇编程序名称  
  
- CC：C编译器名称  
  
- CXX：C++编译器名称  
  
- CPP：C预编译器名称  
  
- **FLAGS：**为不同编译器名称，表示对应编译器的参数  
  
- LD：链接器名称  
  
- AR：归档器archiver名称  
  
- RANLIB：符号表添加器名称（AR和RANLIB是什么具体看这里）  
  
##   
## 获取样本  
  
1. 自己随便写，fuzzer会自己变异，但效率较低。  
  
1. 从网上（github、官网、压缩包自带）找现成的样本sample。  
  
```
cd $HOME/fuzz_target/fuzzing_xpdf
mkdir pdf_examples && cd pdf_examples
wget https://github.com/mozilla/pdf.js-sample-files/raw/master/helloworld.pdf
wget http://www.africau.edu/images/default/sample.pdf
wget https://www.melbpc.org.au/wp-content/uploads/2017/10/small-example-pdf-file.pdf
```  
  
  
**测试安装程序运行**  
```
$HOME/fuzz_target/fuzzing_xpdf/install/bin/pdfinfo -box -meta $HOME/fuzz_target/fuzzing_xpdf/pdf_examples/helloworld.pdf
```  
##   
## 使用fuzz编译器编译（afl-clang-fast）  
  
  
先删除原先的安装，重新编译安装库。  
```
rm -r install
cd xpdf-3.02
make clean
export LLVM_CONFIG="llvm-config-12"
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --prefix="$HOME/fuzz_target/fuzzing_xpdf/install/"
make
make install
```  
  
  
**fuzz**  
```
afl-fuzz -i $HOME/fuzz_target/fuzzing_xpdf/pdf_examples/ -o $HOME/fuzz_target/fuzzing_xpdf/out/ -s 123 -- $HOME/fuzz_target/fuzzing_xpdf/install/bin/pdftotext @@ $HOME/fuzz_target/fuzzing_xpdf/output
```  
  
  
参数  
  
-i：输入样本路径  
  
-o：输出存储路径  
  
-s：fuzzing时随机数使用的种子，这里为了尽量保证复现结果，设为123  
  
--：目标程序  
  
  
这里的@@不能少，虽然初始输入都来源于设置的-i参数，但我们需要根据程序读取输入的方式进行调整此参数。  
- 加@@：被fuzz的程序从文件读取输入。  
  
- 不加@@：被fuzz的程序从标准输入输出流读取输入。  
  
跑一会就能出结果。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRX8cEb6Uk9LicRIiaD4icPcndCn2vkfkomw1iceEWkG489L92YicN6z2HjiaTA/640?wx_fmt=png "")  
##   
## 动态调试  
  
  
源码编译出带调试符号的文件。  
```
make clean
CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./configure --prefix="$HOME/fuzz_target/fuzzing_xpdf/install/"
make
make install
```  
  
  
运行gdb。  
```
gdb --args $HOME/fuzz_target/fuzzing_xpdf/install/bin/pdftotext $HOME/fuzz_target/fuzzing_xpdf/out/default/crashes/<your_filename> $HOME/fuzz_target/fuzzing_xpdf/output
```  
  
  
追踪crash路径：  
  
  
bt：跑出crash后查看调用路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRXWkzkIv3NAH5ohYYD1OnicmGVY1cfP5WERE2nsSJwm3RQG9lQCaWsGiaw/640?wx_fmt=png "")  
  
报错信息Program received signal SIGSEGV, Segmentation fault，存在内存泄漏。  
  
  
报错位置 _int_malloc (av=av@entry=0x7ffff7c6bb80 <main_arena>, bytes=bytes@entry=128) at malloc.c:3679，glibc报了个错，显然是堆内存出了问题。  
  
  
执行流信息，分析一下可以看出调用过程是循环的，判断为无限循环漏洞。  
  
  
根据函数调用找到漏洞位置。  
  
  
从xpdf/Parse.cc 94行的makeStream调用，一路跟着报错往下翻就会找到这个套娃，这里就不细说了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRXDoyX4FHKG78mv0HA0EebQKXjAbEvDXFBpx4zoxcASGQiawE2LGSVpYw/640?wx_fmt=png "")  
##   
## 漏洞修复  
  
  
下个xpdf4.02源码对比一下就好，修复方式比较简单，加了个变量，记录循环次数，超过一定次数就结束进程。  
```
wget https://dl.xpdfreader.com/old/xpdf-4.02.tar.gz
```  
  
  
  
**Exercise 2 - libexif**  
  
  
CVE-2009-3895（  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3895  
） （heap-based buffer overflow）and CVE-2012-2836（  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2836  
） （Out-of-bounds Read）in libexif 0.6.14  
##   
## 安装调试目标  
  
  
从github等途径下载并解压。  
```
tar -xzvf libexif-0_6_14-release.tar.gz
```  
  
  
安装依赖。  
‍  
```
apt-get install
```  
  
  
配置configure并安装。  
```
autoreconf -fvi 用于适配系统环境，简化config命令
//安装autoreconf sudo apt-get install autopoint libtool gettext libpopt-dev
./configure --enable-shared=no (如果是库文件，必须编译成静态库) --prefix="/root/fuzz_target/fuzzing_libexif/install/"
make
make install
```  
  
  
**获取交互应用（如果调试的是库，需要调用接口fuzz）**  
1. 自己写一个c程序调用接口，用afl提供的编译器编译出来。  
  
1. 直接找调用了库文件的应用，这是这题采用的方法。  
  
##   
## 使用fuzz编译器编译（afl-clang-lto）  
  
  
先删除原先的安装，重新编译安装库。  
```
make clean
export LLVM_CONFIG="llvm-config-12"
CC=/root/fuzz/AFLplusplus/afl-clang-lto ./configure --enable-shared=no --prefix="/root/fuzz_target/fuzzing_libexif/install/"
make
make install
```  
  
  
如果编译不通过，可以加 AR=llvm-ar RANLIB=llvm-ranlib LD=afl-clang-lto  
  
   
  
重新编译应用。  
```
make clean
export LLVM_CONFIG="llvm-config-12"
CC=/root/fuzz/AFLplusplus/afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/fuzz_target/fuzzing_libexif/install/" PKG_CONFIG_PATH=$HOME/fuzz_target/fuzzing_libexif/install/lib/pkgconfig
make
make install
```  
  
  
测试运行。  
```
$HOME/fuzz_target/fuzzing_libexif/install/bin/exif $HOME/fuzz_target/fuzzing_libexif/exif-samples-master/jpg/Canon_40D_photoshop_import.jpg
```  
##   
## fuzz  
```
afl-fuzz -i $HOME/fuzz_target/fuzzing_libexif/exif-samples-master/jpg/ -o $HOME/fuzz_target/fuzzing_libexif/out/ -s 123 -- $HOME/fuzz_target/fuzzing_libexif/install/bin/exif @@
```  
  
##   
##   
## 动态调试  
  
  
编译出带调试信息的可执行文件。  
```
cd libexif-libexif-0_6_14-release
make clean
CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./configure --prefix="$HOME/fuzz_target/fuzzing_libexif/install/"
make
make install

cd exif-exif-0_6_15-release
make clean
CFLAGS="-g -O0" CXXFLAGS="-g -O0" PKG_CONFIG_PATH=$HOME/fuzz_target/fuzzing_libexif/install/lib/pkgconfig ./configure --prefix="$HOME/fuzz_target/fuzzing_libexif/install/"
make
make install
```  
  
  
丢进gdb，跑出crash。  
  
### crash1  
```
gdb --args ./install/bin/exif ./out/default/crashes/id\:000000\,sig\:11\,src\:000281\,time\:64869\,execs\:64957\,op\:havoc\,rep\:16
```  
###   
  
报错信息Program received signal SIGSEGV, Segmentation fault.，存在内存泄漏。  
  
  
报错位置exif_get_sshort (buf=0x555655563195 <error: Cannot access memory at address 0x555655563195>, order=EXIF_BYTE_ORDER_MOTOROLA) at exif-utils.c:92，注意这里的报错，内存地址无法访问，再看地址，估计为堆缓冲区溢出。  
  
###   
### crash2  
```
gdb --args ./install/bin/exif ./out/default/crashes/id\:000002\,sig\:11\,src\:000301\,time\:126417\,execs\:126621\,op\:havoc\,rep\:8
```  
  
###   
  
报错信息Program received signal SIGSEGV, Segmentation fault.，存在内存泄露。  
  
  
报错位置__memmove_avx_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:345。  
###   
### crash3  
```
gdb --args ./install/bin/exif ./out/default/crashes/id\:000006\,sig\:11\,src\:000492+000181\,time\:341313\,execs\:358541\,op\:splice\,rep\:8
```  
###   
###   
  
报错信息Program received signal SIGSEGV, Segmentation fault，存在内存泄露。  
  
  
报错位置exif_get_slong (b=0x555555582000 <error: Cannot access memory at address 0x555555582000>, order=EXIF_BYTE_ORDER_MOTOROLA) at exif-utils.c:135，与1类似。  
  
##   
## 漏洞修复  
##   
## https://github.com/libexif/libexif/commit/8ce72b7f81e61ef69b7ad5bdfeff1516c90fa361  
##   
## https://github.com/libexif/libexif/commit/00986f6fa979fe810b46e376a462c581f9746e06  
#   
  
# Exercise 3 - tcpdump(使用ASAN)  
  
  
CVE-2017-13028（  
https://www.cvedetails.com/cve/CVE-2017-13028/  
） in TCPdump 4.9.2（Out-of-bounds Read）  
  
   
  
libcap是tcpdump的依赖库，可以不install，但需要保证目录位置与tcpdump根目录相同，且名称可识别。  
  
## 使用ASAN编译  
```
cd $HOME/fuzz_target/fuzzing_tcpdump/libpcap-1.8.0/
export LLVM_CONFIG="llvm-config-12"
CC=/root/fuzz/AFLplusplus/afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/fuzz_target/fuzzing_tcpdump/install/"
AFL_USE_ASAN=1 make
AFL_USE_ASAN=1 make install
 
cd $HOME/fuzz_target/fuzzing_tcpdump/tcpdump-tcpdump-4.9.2/
AFL_USE_ASAN=1 CC=/root/fuzz/AFLplusplus/afl-clang-lto ./configure --prefix="$HOME/fuzz_target/fuzzing_tcpdump/install/"
AFL_USE_ASAN=1 make
AFL_USE_ASAN=1 make install
```  
  
## 这里配置tcpdump的configure时也要加AFL_USE_ASAN=1，因为它的依赖库也加了ASAN。  
##   
## fuzz  
```
afl-fuzz -m none -i ./tcpdump-tcpdump-4.9.2/tests/ -o ./afl_out/ -s 123 -- ./install/sbin/tcpdump -vvvvXX -ee -nn -r @@
```  
##   
## ASAN会消耗大量内存，使用-m none不限制内存使用。  
  
   
  
这个我跑了比较久（挂着进程容易忘关）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRXo9qsCzns918DP2CwnS4XmRWMGPa1kG3bFSj8VEk9uIoVmaafzbywIQ/640?wx_fmt=png "")  
##   
## 动态调试  
  
  
有ASAN就不用再重新编译整个文件来调试了（这里如果用普通编译来运行crash反而得不到报错信息，显然这里的内存泄露不会直接导致crash）。  
```
./install/sbin/tcpdump -vvvvXX -ee -nn -r ./afl_out/default/crashes/id\:000000\,sig\:06\,src\:011483\,time\:43941578\,execs\:17770128\,op\:havoc\,rep\:8
```  
  
  
直接运行crash，ASAN会给出较为详细的报错和调用栈。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRXM2kpU4yrsIY7Th8eAYvYANGUnff9VleLEqswGDianHUxKnsiaf4HHGMg/640?wx_fmt=png "")  
  
报错信息：AddressSanitizer: heap-buffer-overflow /root/fuzz_target/fuzzing_tcpdump/tcpdump-tcpdump-4.9.2/./extract.h:184:20 in EXTRACT_16BITS，直接说明是堆溢出。  
##   
## 漏洞修复  
##   
## https://github.com/the-tcpdump-group/tcpdump/commit/85078eeaf4bf8fcdc14a4e79b516f92b6ab520fc#diff-05f854a9033643de07f0d0059bc5b98f3b314eeb1e2499ea1057e925e6501ae8L381  
#   
  
# Exercise 4 - libtiff（coverage优化）  
  
  
CVE-2016-9297（  
https://www.cvedetails.com/cve/CVE-2016-9297/  
） in libtiff 4.0.4 （Out-of-bounds Read）  
##   
## 使用lvoc（覆盖率检测）编译libtiff  
```
CFLAGS="--coverage" LDFLAGS="--coverage" ./configure --prefix="$HOME/fuzz_target/fuzzing_tiff/install/" --disable-shared
make
make install
```  
  
## 获取覆盖率  
```
cd $HOME/fuzzing_tiff/tiff-4.0.4/
lcov --zerocounters --directory ./
lcov --capture --initial --directory ./ --output-file app.info
$HOME/fuzz_target/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w $HOME/fuzz_target/fuzzing_tiff/tiff-4.0.4/test/images/palette-1c-1b.tiff
lcov --no-checksum --directory ./ --capture --output-file app2.info
```  
##   
## lcov --zerocounters --directory ./：重置计数器。  
##   
## lcov --capture --initial --directory ./ --output-file app.info：为每个instrumented line返回覆盖率数据的初始化基准。  
##   
## $HOME/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w $HOME/fuzzing_tiff/tiff-4.0.4/test/images/palette-1c-1b.tiff0：运行需要分析的应用，可以用多个样本运行多次。  
##   
## lcov --no-checksum --directory ./ --capture --output-file app2.info：保存覆盖率状态。  
  
  
将结果转化生成HTML输出。  
```
genhtml --highlight --legend -output-directory ./html-coverage/ ./app2.info
```  
  
  
**编译文件**  
```
export LLVM_CONFIG="llvm-config-12"
CC=/root/fuzz/AFLplusplus/afl-clang-lto ./configure --prefix="$HOME/fuzz_target/fuzzing_tiff/install/" --disable-shared
AFL_USE_ASAN=1 make -j4
AFL_USE_ASAN=1 make install
afl-fuzz -m none -i $HOME/fuzz_target/fuzzing_tiff/tiff-4.0.4/test/images/ -o $HOME/fuzz_target/fuzzing_tiff/out/ -s 123 -- $HOME/fuzz_target/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w @@
```  
  
  
这里使用尽可能多的参数，增大fuzz到漏洞代码的概率。  
  
## fuzz  
```
afl-fuzz -m none -i $HOME/fuzz_target/fuzzing_tiff/tiff-4.0.4/test/images/ -o $HOME/fuzz_target/fuzzing_tiff/afl_out/ -s 123 -- $HOME/fuzz_target/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w @@
```  
  
##   
##   
## 动态调试  
  
  
查看报错  
```
./install/bin/tiffinfo -D -j -c -r -s -w ./out/default/crashes/id\:000000\,sig\:06\,src\:000016\,time\:556815\,execs\:377779\,op\:havoc\,rep\:4
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRX9sky9PNDOibH0h1XtrD9ibVsZOCEmR137NvD3JvoOmdiaOLk1UK0rp3Kw/640?wx_fmt=png "")  
  
  
报错信息：AddressSanitizer: heap-buffer-overflow (/root/fuzz_target/fuzzing_tiff/install/bin/tiffinfo+0x2aaf11) in fputs，堆溢出。  
##   
## 漏洞修复  
##   
## https://github.com/vadz/libtiff/commit/30c9234c7fd0dd5e8b1e83ad44370c875a0270ed  
#   
#   
# Exercise 5 - libxml2（自定义字典、并行）  
  
  
CVE-2017-9048（  
https://nvd.nist.gov/vuln/detail/CVE-2017-9048  
） in LibXML2 2.9.4（stack buffer overflow）  
##   
## 字典用途  
  
  
本质上就是有一定意义的字符串token。  
- Override：直接覆盖样本中的n个字节  
  
- Insert：在样本中插入n个字节  
  
AFL++提供了先成的字典。  
https://github.com/AFLplusplus/AFLplusplus/tree/stable/dictionaries  
（可以凑合）  
  
   
  
也可以自己手动构建，用codeql（在线平台LGTM）可以快速查询我们需要的特征字符串如：  
- 判断的条件  
  
- strcmp、memcmp中的参数  
  
- 声明的常量等  
  
##   
## 并行  
  
  
将fuzzer分为master和slave，实现共享instance  
```
./afl-fuzz -i afl_in -o afl_out -M Master -- ./program @@
```  
```
./afl-fuzz -i afl_in -o afl_out -S Slave1 -- ./program @@
./afl-fuzz -i afl_in -o afl_out -S Slave2 -- ./program @@
...
./afl-fuzz -i afl_in -o afl_out -S SlaveN -- ./program @@
```  
  
  
**编译文件**  
```
sudo apt-get install python-dev
CC=/root/fuzz/AFLplusplus/afl-clang-lto CXX=/root/fuzz/AFLplusplus/afl-clang-lto++ CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ./configure --prefix="$HOME/fuzz_target/fuzzing_libxml2/libxml2/install" --disable-shared --without-debug --without-ftp --without-http --without-legacy --without-python LIBS='-ldl'
AFL_USE_ASAN=1 AFL_MAP_SIZE=262144 make -j$(nproc)
AFL_USE_ASAN=1 AFL_MAP_SIZE=262144 make install
```  
  
  
这里在编译时没有直接用ASAN，而是用了编译器自带的fsanitize，功能如下：  
  
-fsanitize=leak：  
检测内存泄漏。  
  
-fsanitize=address：  
检测内存越界，这等于ASAN。  
  
  
编译时设置AFL_MAP_SIZE=262144，决定共享空间大小，因为程序较大，不改成一个较大值会给弹一个警告，最好设置一下。  
##   
## 获取样本和字典  
  
  
这里用的是fuzzing101提供的样本以及test中的dtd9（DTD，它们会定义 XML 文档的结构和合法元素/属性，并用于确定 xml 文档是否有效）。  
```
mkdir afl_in && cd afl_in
wget https://raw.githubusercontent.com/antonio-morales/Fuzzing101/main/Exercise%205/SampleInput.xml
cd ..
```  
  
  
使用AFL++提供的字典。  
```
mkdir dictionaries && cd dictionaries
wget https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/dictionaries/xml.dict
cd ..
```  
##   
## fuzz  
```
afl-fuzz -m none -i ./afl_in -o afl_out -s 123 -x ./dictionaries/xml.dict -D -M master -- ./xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@
afl-fuzz -m none -i ./afl_in -o afl_out -s 234 -S slave1 -- ./xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@
```  
## -D：打开persistent mutations  
  
  
然后要跑很久，居然是靠havoc出的让我很意外。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRXwwwPkreSlCPHuDL1kJicNTZ9IfaibxDmHTfYjz1p1pLxgLHR9SYm0iaOg/640?wx_fmt=png "")  
  
##   
## 动态调试  
  
  
先手动编译出不插桩的程序，丢进gdb里调试。  
```
gdb --args ./xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude ./afl_out/slave1/crashes/id:000009,sig:06,src:009269,time:119653664,execs:60774850,op:havoc,rep:4
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRXoeUYiaRHF2hWH1FKryDSZbZNuHm2rRPuXx5EexHe2OYqWBYhFZxIhcA/640?wx_fmt=png "")  
  
  
报错信息*** stack smashing detected ***: terminated，判断为栈溢出漏洞。  
  
  
漏洞位置__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50，找到问题代码。  
##   
## 漏洞修复  
  
  
https://github.com/GNOME/libxml2/commit/932cc9896ab41475d4aa429c27d9afd175959d74  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ERaic4xv4heDbN3icCd4lfRXeCYibFMLJ3UIBFkJPm9WnBs5BEiclErm0vDn9HwUYvs745l7VRWicoCfA/640?wx_fmt=png "")  
  
  
**看雪ID：Azyka**  
  
https://bbs.pediy.com/user-home-958400.htm  
  
*本文由看雪论坛 Azyka 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458458572&idx=3&sn=f4516c969b2a0919f9ed1d3053ca6f0a&chksm=b18e294686f9a050bd0e9d9ca8309de05ae9c06af6c162ba1fa2f1e98ddeb7407fa81b3b4e57&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1.[CobaltStrike ShellCode详解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458460264&idx=1&sn=52e25757888a3df53e8c6d01c7a0229d&chksm=b18e10e286f999f4d1377a09747bfcb8f2ec5dc8ee757c1e69d5b198403571dd9b5386531ad9&scene=21#wechat_redirect)  
  
  
2.[Android APP漏洞之战——SQL注入漏洞初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458460061&idx=1&sn=ce272d6b2b2f839d7eeeb2896eb90ee5&chksm=b18e2f1786f9a60139d90f95e9442cc01b6f218f6bd47045dbdeb25d946d7427ba16c9c24cd9&scene=21#wechat_redirect)  
  
  
3.[House of apple 一种新的glibc中IO攻击方法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459847&idx=1&sn=f4afaf30634e626ce539023d1de675fe&chksm=b18e2e4d86f9a75bf414e6332f9cfb5601fffe6f3388d5810971b0e92738fe640552ea889841&scene=21#wechat_redirect)  
  
  
4.[so文件分析的一些心得](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459775&idx=1&sn=6c0c9339f1ffc06d3eba9a4e595e75ff&chksm=b18e2ef586f9a7e384e18d417ac75f9c2d12d1364b5c5f14dc1b42a7fc94b0f4d5e75c0e4d4e&scene=21#wechat_redirect)  
  
  
5.[从PWN题NULL_FXCK中学到的glibc知识](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459387&idx=1&sn=e2565825c7a6bca43d4b0a5b35d642c2&chksm=b18e2c7186f9a56757279ef7fe8afc1c2c3a57dc74c545180f5eb0d16f86d50f2aa52da62a59&scene=21#wechat_redirect)  
  
  
6.[指令级工具Dobby源码阅读](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459349&idx=1&sn=c7befdac063330a9ada2e3d1b0e396ef&chksm=b18e2c5f86f9a5492113d4584d85a484eedb3384f8e4ad14235273dd830e4cd57615f08ec926&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  
