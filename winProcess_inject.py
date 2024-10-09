#!python
# -*- coding:utf-8 -*-
# 导入sys库以及ctypes库
import sys
from ctypes import *

import psutil
import win32api
import codecs


PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM = (0x1000 | 0x2000)

# kernel32 = windll.kernel32
kernel32 = windll.LoadLibrary("kernel32.dll")


def inject(pid, data, parameter=0):
    print(data)
    # data = bytes(data, encoding="utf8")  # 注意！！一定要做ascii编码转换
    # data = bytes(data)  # 注意！！一定要做ascii编码转换
    # print(data)
    # Get a handle to the process we are injecting into.
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
    print("h_process: %s" % h_process)
    if not h_process:
        print("[*] Couldn't acquire a handle to PID: %s" % pid)
    arg_address = kernel32.VirtualAllocEx(h_process, 0, len(data), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    print("arg_address: %s" % arg_address)
    written = c_int(0)
    kernel32.WriteProcessMemory(h_process, arg_address, data, len(data), byref(written))
    print("written: %s" % written)
    thread_id = c_ulong(0)
    if not parameter:   # 判断是shellcode 还是 DLL
        start_address = arg_address
    else:
        h_kernel32 = win32api.GetModuleHandle("kernel32.dll")
        start_address = win32api.GetProcAddress(h_kernel32, "LoadLibraryA")
        parameter = arg_address
    # if not kernel32.CreateRemoteThread(h_process, None, 0, start_address, parameter, 0, byref(thread_id)):
    #     print("[*] Failed to inject the DLL. Exiting.")
    #     sys.exit(0)
    print("thread_id: %s" % thread_id)
    return True


def get_pid(pro_name):
    pids = psutil.pids()
    # 第二步在快照中去比对给定的进程名
    for pid in pids:
        try:
            p = psutil.Process(pid)
            if pro_name and p.name() == pro_name:
                return pid
        except:
            continue
    return 0


if __name__ == '__main__':
    pid = get_pid("test.exe")
    # pid = 24076
    print(pid)
    shellcode = "\x31\xd2\xb2"
    # inject(pid, shellcode)
    inject(pid, "WxInject_Dll.dll", 1)
    # inject(pid, connect_back_shellcode, 0)
