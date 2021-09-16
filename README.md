WslinkVMAnalyzer
================

WslinkVMAnalyzer is a tool primarily developed to facilitate analysis of
[Wslink](https://www.welivesecurity.com/2021/10/27/wslink-unique-undocumented-malicious-loader-runs-server/),
which is a unique loader running as a server and executing received modules in-memory. This tool uses [Miasm](https://github.com/cea-sec/miasm), an open
source framework that provides us with a symbolic execution engine.

The tool and structure of the virtual machine is described in our [blogpost](https://www.welivesecurity.com/2022/03/28/under-hood-wslink-multilayered-virtual-machine/).

Install
-------

    % pip3 install https://github.com/eset/wslink-vm-analyzer/archive/refs/heads/master.tar.gz

Example usage
-------------

In the ``examples`` directory, you will find a dump of the virtual machine and
two Python scripts. The scripts output Graphviz DOT files (``vma.dot``) which
can by converted to SVG or any other format supported by Graphviz.

    (./examples) % python3 VM1.py
    (./examples) % dot -Tsvg vma.dot -o vma.svg
