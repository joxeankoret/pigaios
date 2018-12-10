# Pigaios

Pigaios ('πηγαίος', Greek for 'source' as in 'source code') is a tool for diffing/matching source codes directly against binaries. The idea is to point a tool to a code base, regardless of it being compilable or not (for example, partial source code or source code for platforms not at your hand), extract information from that code base and, then, import in an IDA database function names (symbols), structures and enumerations. It uses the Python CLang bindings (which are very limited, but still better than using pycparser).

Basically, the tool does the following:

 * Parse C source code and extract features from the Abstract Syntax Tree (AST) of each function.
 * Export the same data extracted from C source codes from IDA databases.
 * Find matches between the features found in C source codes and IDA databases.
 * After an initial set of matches with no false positive is found, find more matches from the callgraph.
 * Rate the matches using both an "expert system" and a "machine learning" based system.
 * Also, import into the IDA database all the required structures and enumerations of a given code base (something not trivial in IDA).
 
The tool was released in October 2018, during the [Hacktivity](https://www.hacktivity.com/) conference.

## Donations

You can help (or thank) the author of Pigaios by making a donation, if you feel like doing so: [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=LKGZZNUCZFYG8&source=url)

## Requirements

This project requires the installation of the CLang's Python bindings, Colorama is required for displaying colours (but is optional) and SciKit Learn is required for the Machine Learning part (which is also optional). You can install in Debian based Linux distros the dependencies with the following command:
 
```
$ sudo apt-get install clang python-clang-5.0 libclang-5.0-dev python-colorama python-sklearn
```

In other operating systems, like in Windows, you can install them by issuing the following commands:

```
$ pip install clang-5
$ pip install colorama
$ pip install scikit-learn
```

In Windows, it's also required to install LLVM *and* to add LLVM to the system PATH for all users or at least the current user. You can use the pre-built binaries: http://releases.llvm.org/download.html

NOTE: There is no strong requirement on the specific 5.0 version of the Python CLang bindings, it should work with any CLang version higher or equal to 3.9. However, most of the testing have been done with version 5.0.

## Using srctobindiff

We will use as an example the source code tarball of [Zlib 1.2.11](https://zlib.net/zlib-1.2.11.tar.gz). Download it and untar the archive in a directory. Then enter into that directory and run the command "srcbindiff.py -create":

```
$ wget https://zlib.net/zlib-1.2.11.tar.gz
$ tar -xzf zlib-1.2.11.tar.gz 
$ cd zlib-1.2.11
$ srcbindiff.py -create
Project file 'sbd.project' created.
```

By default, a project file 'sbd.project' will be created. Open this newly generated file in your favourite text editor, you will see something like the following:

```
$ cat sbd.project 
####################################################
# Default Source-Binary-Differ project configuration
####################################################
[GENERAL]
includes = /usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include

[PROJECT]
cflags = -Izlib_dir -Izlib_dir/include
cxxflags = -Izlib_dir -Izlib_dir/include
export-file = zlib-1.2.11.sqlite

[FILES]
examples/gzjoin.c = 1
examples/fitblk.c = 1
examples/enough.c = 1
examples/gzappend.c = 1
examples/zran.c = 1
examples/zpipe.c = 1
examples/gzlog.c = 1
examples/gun.c = 1
contrib/testzlib/testzlib.c = 1
contrib/iostream/test.cpp = 1
(...many other files stripped...)
```

In this file we can see various directives:

 * The compiler/frontend required include headers.
 * The CFLAGS and CXXFLAGS that we want to use for parsing the source code files.
 * A list of source files and a number indicating if the files are enabled for compilation or not (1 or 0).
 
We will just remove all the lines for the files in "examples/" or "test/". After that, we will run again the "srcbindiff.py" program passing the "-export" command line option:

```
$ srcbindiff.py -export
Using a total of 8 thread(s)
[+] CC examples/gzjoin.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CC examples/fitblk.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CC examples/enough.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CC examples/gzappend.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CC examples/zran.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CC examples/zpipe.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CC examples/gzlog.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CC examples/gun.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
examples/zran.c:402,68: warning: format specifies type 'unsigned long long' but the argument has type 'off_t' (aka 'long')
[+] CC contrib/testzlib/testzlib.c -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CXX contrib/iostream/test.cpp -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
contrib/testzlib/testzlib.c:3,10: fatal: 'windows.h' file not found
[+] CXX contrib/iostream/zfstream.cpp -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
contrib/iostream/zfstream.h:5,10: fatal: 'fstream.h' file not found
contrib/iostream/zfstream.h:5,10: fatal: 'fstream.h' file not found
[+] CXX contrib/iostream3/test.cc -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
[+] CXX contrib/iostream3/zfstream.cc -I/usr/lib/llvm-3.8/bin/../lib/clang/3.8.0/include -I. -I./include
(...)
[+] Building definitions...
[i] Creating headers definition file zlib-1.2.11-exported.h...
[+] Building the callgraphs...
[+] Building the constants table...
[+] Creating indexes...
```

As we can see, it compiled, parsed and generated everything from the source code and the process generated various warnings and errors. The errors are because I'm compiling the ZLib source code in Linux and I don't have the windows.h header, for example. We can remove the files that are failing or we can just ignore them as one feature of this project is that it can parse both partial and non compilable source codes. Whatever we decide to do, we will have a SQLite database called "zlib-1.2.11.sqlite" in the same directory where we ran the command. We can open that database with whatever tool that supports SQLite databases, if we want to do so, like its command line tool:

```
$ sqlite3 zlib-1.2.11.sqlite 
SQLite version 3.11.0 2016-02-15 17:29:24
Enter ".help" for usage hints.
sqlite> select name from functions limit 5;
BeginCountPerfCounter
BeginCountRdtsc
Display64BitsSize
ExprMatch
ExprMatch
```

## Importing symbols in IDA

Once we have a binary opened in IDA that we know is using ZLib we can match functions directly from the source code by running the IDAPython script ```sourceimp_ida.py``` and selecting in the dialog the zlib-1.2.11.sqlite file we just exported before. After a few seconds, it will discover various functions by, first, just issuing some simple SQL queries and, later on, will find many more symbols by traversing the call graph of the initial matches (that should have near zero false positives) and find more matches. At the same time, you should have all the structures and enumerations that were found while parsing the ZLib source code.

And that's it! Hopefully, it will make the life of reverse engineers easier and we will have to spend less time doing boring tasks like importing symbols or waste time reverse engineering open source libraries statically compiled in our targets.

## License

Pigaios is released under the GPL v3 license but commercial licenses for proprietary developments can be purchased. Contact admin AT joxeankoret DOT com for more details.
