# eBPF (extended Berkeley Packet Filter) for Kernel Security and Real-Time Network Management
### NOTICE: this project is mainly built on `ubuntu 21.10`
There will be some environmental issue when building on other linux versions.
- [Installing BCC](#installing-bcc)
- [Project_1](#project_1)
- [Project_2](#project_2)
- [Project_3](#project_3)
- [Project_4](#project_4)

## Installing BCC (BPF Compiler Collection)
### Install build dependencies
```console
$ sudo apt install -y bison build-essential cmake flex git libedit-dev libllvm11 llvm-11-dev libclang-11-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils clang-11 libbfd-dev libcap-dev
```

### Install and compile BCC
```console
$ git clone https://github.com/iovisor/bcc.git
$ mkdir bcc/build; cd bcc/build
$ cmake ..
$ make
$ sudo make install
$ cmake -DPYTHON_CMD=python3 .. # build python3 binding
$ pushd src/python/
$ make
$ sudo make install
$ popd
```

## Project_1: We Got Your Password!
### Install [logkeys](https://github.com/kernc/logkeys)
Please change into directory `Project_1` first.
```console
$ sudo apt install autotools-dev autoconf kbd
$ git clone https://github.com/kernc/logkeys.git
$ cd logkeys
$ ./autogen.sh     # generate files for build
$ cd build         # keeps the root and src dirs clean
$ ../configure
$ make
$ sudo make install
```
### How to run
1. Change into directory `Project_1`.
2. Create `out.log` file to record.
```console
$ touch out.log
```
3. Run `keylog.py`.
```console
$ sudo python3 keylog.py
```
4. In anothor terminal, see what is writing into `out.log`.
```console
$ sudo tail --follow out.log
```
5. In anothor terminal, try to type some commands. Once you type `sudo` command, you will see that keylogger is recording what you  are typing.
```console
$ sudo ls
```
### logkeys outputs wrong characters
It is very likely that you will see only some characters recognized. In this case, open `my_lang.keymap` in UTF-8 enabled text editor and manually repair any missing or incorrectly determined mappings.


## Project_2: Insert Anything , Anywhere!
Please change into directory `Project_2` first.
### How to run
1. Run `is_file.py`.
```console
$ sudo python3 ./is_file.py "<your preferred text here>"
```
2. In anothor terminal, try to read `test` file. You can see the different by reading `test` file before and after running `is_file.py`.
```console
$ cat test
```
### Input size out of buffer
You may encounter a situation where you enter too many words. In this case, you will receive an error message: `Out of buffer, please make your input size smaller.`

## Project_3: An eBPF-Based Firewall Using XDP
Please change into directory `Project_3` first.
### How to run
1. Run `main.py`.
```console
$ sudo python3 main.py
```
2. Try sending any TCP/UDP packages in ipv4/ipv6 to the kernel, and observe what is different before and after running `main.py`.
For example:
```console
// for ipv4/TCP packages
$ nc -4 -l localhost 7999
<will receive something>

$ nc -4 localhost 7999
<type something here>

// for ipv4/UCP packages
$ nc -4 -u -l localhost 7999
<will "not" receive anything>

$ nc -4 -u -l localhost 7998
<will receive something>

$ nc -4 -u localhost 7999
<type something here>

// for ipv6/UDP packages
$ nc -6 -u -l localhost 7999
<will "not" receive anything>

$ nc -6 -u localhost 7999
<type something here>
```
### Our rules of transporting packages
TCP/UDP \ ip ver.|ipv4|ipv6
--|--|---
TCP to port 7999|pass|drop
UDP to port 7999|redirect to port 7998| drop

## Project_4: eBPF-Hooked Command-Line Killer
Please change into directory `Project_4` first.
### Generate binaries
The binaries will built into `Project_4/src/bin`.
1. Change into directory `Project_4`.
2. Build binaries.
```console
$ chmod +x tools/bpftool
$ cd src
$ make
```
### How to run
1. Change into directory `Project_4/src/bin`
2. Run `bpfKillExecve`
```console
$ sudo ./bpfKillExecve
```
3. Try to do anything in another terminal. You will see any process who is trying to use `execve syscall` be killed.
```console
$ ls
Killed

$ sudo
Killed

...
```