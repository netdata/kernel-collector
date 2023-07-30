<!--
Describe the change in summary section, including rationale and design decisions.
Include "Fixes #nnn" if you are fixing an existing issue.

In "Test Plan" provide enough detail on how you plan to test this PR so that a reviewer can validate your tests. If our CI covers sufficient tests, then state which tests cover the change.

If you have more information you want to add, write them in "Additional
Information" section. This is usually used to help others understand your
motivation behind this change. A step-by-step reproduction of the problem is
helpful if there is no related issue.
-->

##### Summary

##### Test Plan
1. Get binaries according your LIBC from [this](ADD ACTIONS LINK HERE) link and extract them inside a directory, for example: `../artifacts`.
You can also get everything for glibc [here](UPLOAD FILE WITH ALL BINARIES TO SIMPLIFY REVIEWERS).

2. Extract them running:
    ```sh
    $ for i in `ls *.zip`; do unzip $i; rm .gitkeep ; rm $i; done
    $ for i in `ls *.xz`; do tar -xf $i; rm $i* ; done
    ```

3. Compile branch an run the following tests:

    ```sh
    # make clean; make tester
    # for i in `seq 0 3`; do ./kernel/legacy_test --netdata-path ../artifacts --content --iteration --pid $i --log-path file_pid$i.txt; done
    ```

4. Every test should ends with `Success`, unless you do not have a specific target (function) available.

##### Additional information

This PR was tested on:

| Linux Distribution |   Environment  |Kernel Version | Real Parent | Parent |  All |
|--------------------|----------------|---------------|-------------|--------|------|
| LINUX DISTRIBUION  | Bare metal/VM  | uname -r      |             |        |      |
