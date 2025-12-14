#!/usr/bin/env python3
#
# Minimal failing test sequence finder
# Copyright (c) 2022, Qualcomm Innovation Center, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import subprocess
import sys
from colorama import Fore, Style

def red(s, bright=False):
    tmp = Style.BRIGHT if bright else ''
    return tmp + Fore.RED + s + Style.RESET_ALL

def yellow(s, bright=False):
    tmp = Style.BRIGHT if bright else ''
    return tmp + Fore.YELLOW + s + Style.RESET_ALL

def bright(s):
    return Style.BRIGHT + s + Style.RESET_ALL

def run_tests(tests):
    print(yellow("Run test sequence: ") + ' '.join(tests))
    arg = ['./vm-run.sh'] + tests
    cmd = subprocess.Popen(arg, stdout=subprocess.PIPE)
    out = cmd.stdout.read().decode()
    found = False
    for i in out.splitlines():
        if i.startswith('FAIL '):
            t = i.split(' ')[1]
            if t == tests[-1]:
                found = True
            else:
                print(red("Unexpected FAIL: ", bright=True) + t)
                return None
    return found

def reduce(tests):
    if len(tests) < 2:
        return None

    # Try to remove first half of the test cases to speed up the initial process
    if len(tests) > 10:
        a = list(tests[int(len(tests) / 2):])
        res = run_tests(a)
        if res is None:
            return None
        if res:
            return a

    # Try to remove test cases one-by-one (starting with larger groups to speed
    # up)
    for count in [27, 9, 6, 3, 1]:
        for i in range(0, len(tests) - count, count):
            b = list(tests)
            del b[i:i + count]
            if len(b) < 2:
                continue
            res = run_tests(b)
            if res is None:
                return None
            if res:
                return b

    return None

def main():
    tests = sys.argv[1:]
    num_tests = len(tests)
    if not run_tests(tests):
        print(red("Full test sequence did not result in an error", bright=True))
        return
    while True:
        new_tests = reduce(tests)
        if (not new_tests) or len(new_tests) == len(tests):
            break
        tests = new_tests
        print(yellow("Found a shorter sequence: ", bright=True) + ' '.join(tests))
    if len(tests) < num_tests:
        print(bright("Minimal sequence:"))
        print(' '.join(tests))
    else:
        print(yellow("Could not remove any test cases without losing the failure"))

if __name__ == "__main__":
    main()
