ASGCT Bottom
============

An Agent that checks the bottom-most frame returned by AsyncGetCallTrace is correct (using GST), thereby checking that ASGCT
does not abort the stack walking too early.

This is extracted from my [trace_validation](https://github.com/parttimenerd/trace_validation) project.
Read more on the topic of correctness in my blog post [Validating Java Profiling APIs](https://mostlynerdless.de/blog/2023/03/14/validating-java-profiling-apis/).

It's quite simple to use (on Linux):

```sh

# build it
./build.sh

# get some benchmarks
test -e renaissance.jar || wget https://github.com/renaissance-benchmarks/renaissance/releases/download/v0.14.2/renaissance-gpl-0.14.2.jar -O renaissance.jar

# run it, e.g.
./run.sh -jar renaissance.jar -r dotty

# or equally
java -agentpath=./libbottom.so -jar renaissance.jar -r dotty
```

The last two commands should both result in something like the following if you have a version that contains [PR 12535](https://github.com/openjdk/jdk/pull/12535):

```
agCheckedTraces           :      13407    100.000%
  broken                  :          0      0.000%
    bottom frame differs  :          0       -nan%   // trace is cut off
    of all: classloader   :          0       -nan%   // classloader related
    of all: far larger    :          0       -nan%
```

Or if not:

```
agCheckedTraces           :       4064    100.000%
  broken                  :       1711     42.101%
    bottom frame differs  :       1711    100.000%
    of all: classloader   :          0      0.000%
    of all: far larger    :         43      2.513%
```

Using the `help` option prints all available options.

**Important**: The agent might report false positives.

**Important on Mac**: The agent supports Mac, but might crash with segfaults.

If you find any broken traces, please check whether they are also appearing
with OpenJDK master and report them either to me (via issues here, Twitter or mail) or by opening a JBS issue. I'm happy to help fixing them.

Developer Notes
---------------

To get proper editor support for the C++ code, use VSCode with the clangd extension and
run `bear -- ./build.sh` to generate a `compile_commands.json` file.

License
-------
MIT, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger
and trace-validation contributors


*This project is a tool of the [SapMachine](https://sapmachine.io) team
at [SAP SE](https://sap.com)*