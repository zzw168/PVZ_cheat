import ctypes
from ctypes import *
import binascii

import psutil
import win32event

import winProcess_get32Model

PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
# PROCESS_ALL_ACCESS = 0x001F0FFF
THREAD_ALL_ACCESS = 0x001F03FF
VIRTUAL_MEM = (0x1000 | 0x2000)
MEM_RELEASE = 0x00008000

# kernel32 = windll.kernel32
kernel32 = windll.LoadLibrary("kernel32.dll")


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


# 取得地址值
def GetValue(hProcess, address, bufflength):
    ReadProcessMemory = winProcess_get32Model.kernel32.ReadProcessMemory
    # print(ReadProcessMemory)
    addr = ctypes.c_ulong()
    ReadProcessMemory(int(hProcess), int(address), ctypes.byref(addr), bufflength, None)  # 读内存
    print("0x%X" % addr.value)
    return addr.value


# 写内存值
def SetValue(hProcess, address, newdata, bufflength):
    WriteProcessMemory = winProcess_get32Model.kernel32.WriteProcessMemory
    newdata = ctypes.c_int64(int(newdata))  # 第二种 shellcode 转换
    print(newdata)
    written = c_int(0)
    # 把内存属性修改为可读写
    winProcess_get32Model.kernel32.VirtualProtectEx(hProcess, address, bufflength, PAGE_EXECUTE_READWRITE,
                                                    byref(written))
    # print('b_protect: %d' % b_protect)
    # print('written: %s' % str(written))
    # print('error: %d' % winProcess_get32Model.kernel32.GetLastError())
    WriteProcessMemory(int(hProcess), address, bytes(newdata), bufflength, None)  # 修改内存地址


# 处理8位地址排序
def Deal_Addr(num):
    if num < 0:
        num = 0x100000000 + num
    a = "%X" % num
    if len(a) < 8:  # 补齐8位
        for i in range(0, 8 - len(a)):
            a = "0" + a
    elif len(a) > 8:
        a = a[len(a) - 7:-1]
    b = ""
    for i in range(0, len(a), 2):  # 重新排列内存地址数据
        b = (a[i:i + 2]) + b
    return b


# 注入jmp代码 ，人造变量
def inject_code(hProcess, data, jmp_addr, call_num, _var=''):
    # 第一步 申请内存写入处理代码
    s = data.split(" ")
    arg_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    var_address = ''
    print("arg_address: %X" % arg_address)  # 申请代码注入内存
    data = ""
    for i in range(0, len(s)):
        data = data + s[i]
    '''-------------------------替换跳转距离----------------------------'''
    # 替换跳转距离
    num = (jmp_addr + call_num) - (arg_address + len(s))  # 回跳距离（兜一圈）
    jmp_back = Deal_Addr(num)
    data = data[0:-8] + jmp_back  # 替换地址回跳距离
    print(data)
    '''-------------------------替换人造变量----------------------------'''
    if _var != '':
        var_address = kernel32.VirtualAllocEx(hProcess, 0, 5, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        print("var_address: %X" % var_address)  # 申请人造变量
        b = Deal_Addr(var_address)
        print(b)
        data = data.replace(_var, b)
    '''--------------------------------------------------------------'''
    data = binascii.a2b_hex(data)  # shellcode 转换
    written = c_int(0)
    kernel32.WriteProcessMemory(hProcess, arg_address, data, len(data), byref(written))
    print("written: %s" % written)

    # 第二步 修改HOOK地址为 jmp 代码
    num = arg_address - (jmp_addr + 5)
    jmp_forward = Deal_Addr(num)
    data = 'E9' + jmp_forward
    data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
    kernel32.WriteProcessMemory(hProcess, jmp_addr, data, len(data), None)

    address = {
        'arg_address': arg_address,
        'var_address': var_address
    }
    return address


# 远程运行 SHELLCODE
def inject_runcode(hProcess, data, call_addr):
    s = data.split(" ")
    # 申请内存
    arg_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    print("arg_address: %X" % arg_address)
    data = ""
    for i in range(0, len(s)):
        data = data + s[i]
    '''-------------------------替换跳转距离----------------------------'''
    # 替换跳转距离
    num = (call_addr) - (arg_address + len(s) - 2)  # 回跳距离（兜一圈）
    jmp_back = Deal_Addr(num)
    data = data[0:-12] + jmp_back + data[-4:]  # 替换地址回跳距离
    print(data)
    data = binascii.a2b_hex(data)
    '''---------------------------------------------------------------'''
    # 注入代码写入内存
    written = c_int(0)
    kernel32.WriteProcessMemory(hProcess, arg_address, data, len(data), byref(written))
    print("written: %s" % written)

    # 执行远程线程
    thread_id = c_ulong(0)
    if not kernel32.CreateRemoteThread(hProcess, None, 0, arg_address, 0, 0, byref(thread_id)):
        print("[*] Failed to inject the DLL. Exiting.")
        return
    print("thread_id: %s" % thread_id)
    h_Thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, int(thread_id.value))
    print(h_Thread)
    kernel32.WaitForSingleObject(h_Thread, win32event.INFINITE)  # 等待，直到线程被激发
    kernel32.CloseHandle(h_Thread)
    kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)  # 释放内存

    return True


# 获取句柄，模块基址
def get_process(process_name, module_name):
    ProcessId = winProcess_get32Model._GetProcessId(None, process_name)
    if ProcessId == 0:
        return False

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return False

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, module_name)
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return False

    process_msg = {'hProcess': hProcess,
                   'ModuleBaseAddr': ModuleBaseAddr}
    return process_msg


# 处理ESI 的 SHELLCODE
def get_esi(hProcess, esi_addr):
    num = esi_addr
    d = "%X" % num
    if len(d) < 8:  # 补齐8位
        for i in range(0, 8 - len(d)):
            d = "0" + d
    elif len(d) > 8:
        d = d[len(d) - 7:-1]
    esi = ''
    for j in range(0, len(d), 2):
        esi = d[j:j + 2] + ' ' + esi
    return esi


def get_base(hProcess, ModuleBaseAddr, offset_list, num=4):
    addr = ModuleBaseAddr
    for off in offset_list:
        print(off)
        addr = GetValue(hProcess, addr + off, num)
    return addr
