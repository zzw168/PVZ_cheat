# -*- coding:utf-8 -*-
"""
@author:
@file: GetBaseAddr.py
@time: 2020-05-13 21:07
@desc: KeyboArd
"""
import win32process
import win32api  # 调用系统模块
import ctypes  # C语言类型
from win32gui import FindWindow  # 界面
import operator
from ctypes import c_long, c_int, c_uint, c_char, c_ulong, c_ubyte, c_char_p, c_void_p, Structure, windll, sizeof, \
    POINTER, pointer
from ctypes import wintypes as wt

kernel32 = ctypes.windll.LoadLibrary("kernel32.dll")
GetLastError = kernel32.GetLastError

TH32CS_SNAPPROCESS = 0x00000002
dwOwnObj = 0xD2FB94
dwEntityList = 0x4D43AC4
dwGlowObjectManager = 0x528B8B0
m_iGlowIndex = 0xA428
m_iTeamNum = 0xF4
m_Hp = 0x100
TH32CS_SNAPMODULE = 0x00000008
STANDARD_RIGHTS_REQUIRED = 0x000F0000
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [('ExitStatus', ctypes.c_ulonglong),  # 接收进程终止状态
                ('PebBaseAddress', ctypes.c_ulonglong),  # 接收进程环境块地址
                ('AffinityMask', ctypes.c_ulonglong),  # 接收进程关联掩码
                ('BasePriority', ctypes.c_ulonglong),  # 接收进程的优先级类
                ('UniqueProcessId', ctypes.c_ulonglong),  # 接收进程ID
                ('InheritedFromUniqueProcessId', ctypes.c_ulonglong)]  # 接收父进程ID


class PROCESSENTRY32(Structure):
    _fields_ = [('dwSize', c_ulong),
                ('cntUsage', c_ulong),
                ('th32ProcessID', c_ulong),
                ('th32DefaultHeapID', c_void_p),
                ('th32ModuleID', c_ulong),
                ('cntThreads', c_ulong),
                ('th32ParentProcessID', c_ulong),
                ('pcPriClassBase', c_ulong),
                ('dwFlags', c_ulong),
                ('szExeFile', c_char * 260),
                ('th32MemoryBase', c_long),
                ('th32AccessKey', c_long)]


class MODULEENTRY32(Structure):
    _fields_ = [('dwSize', c_long),
                ('th32ModuleID', c_long),
                ('th32ProcessID', c_long),
                ('GlblcntUsage', c_long),
                ('ProccntUsage', c_long),
                ('modBaseAddr', c_long),
                ('modBaseSize', c_long),
                ('hModule', c_void_p),
                ('szModule', c_char * 256),
                ('szExePath', c_char * 260)]


## Process32First
Process32First = windll.kernel32.Process32First
Process32First.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32First.rettype = c_int
## Process32Next
Process32Next = windll.kernel32.Process32Next
Process32Next.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32Next.rettype = c_int
## CreateToolhelp32Snapshot
CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = c_long
CreateToolhelp32Snapshot.argtypes = [c_int, c_int]
## OpenProcess
OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [c_void_p, c_int, c_long]
OpenProcess.rettype = c_long
## GetPriorityClass
GetPriorityClass = windll.kernel32.GetPriorityClass
GetPriorityClass.argtypes = [c_void_p]
GetPriorityClass.rettype = c_long
## CloseHandle
CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [c_void_p]
CloseHandle.rettype = c_int
## Module32First
Module32First = windll.kernel32.Module32First
Module32First.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
Module32First.rettype = c_int
## Module32Next
Module32Next = windll.kernel32.Module32Next
Module32Next.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
Module32Next.rettype = c_int
## GetLastError
GetLastError = windll.kernel32.GetLastError
GetLastError.rettype = c_long


def _GetProcessId(className, windowName):
    hGameWindow = FindWindow(className, windowName)
    pid = win32process.GetWindowThreadProcessId(hGameWindow)[1]
    return pid


def _GetPorcessHandle(pid):
    hGameHandle = win32api.OpenProcess(PROCESS_ALL_ACCESS, 0, pid)
    return hGameHandle


def GetProcessImageBase(ProcessId, moduleName):
    # moduleName = "client_panorama.dll"
    pProcessImageBase = 0
    hModuleSnap = c_void_p(0)
    me32 = MODULEENTRY32()
    me32.dwSize = sizeof(MODULEENTRY32)
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId)

    ret = Module32First(hModuleSnap, ctypes.byref(me32))

    print("ret: %d" % ret)
    if GetLastError() != 0:
        print("hModuleSnap: %d" % hModuleSnap)
        CloseHandle(hModuleSnap)
        print('Handle Error %s' % GetLastError())
        return 'Error'
    else:
        if (Module32First(hModuleSnap, pointer(me32))):
            if me32.szModule.decode() == moduleName:
                # 这里因为是Python3，输出字符会在前面出现一个b'xxx'，所以要先使用decode解码
                CloseHandle(hModuleSnap)
                return me32.modBaseAddr
            else:
                Module32Next(hModuleSnap, pointer(me32))
                while int(GetLastError()) != 18:
                    if me32.szModule.decode() == moduleName:
                        # 这里因为是Python3，输出字符会在前面出现一个b'xxx'，所以要先使用decode解码
                        CloseHandle(hModuleSnap)
                        return me32.modBaseAddr
                    else:
                        Module32Next(hModuleSnap, pointer(me32))
                CloseHandle(hModuleSnap)
                print('Couldn\'t find Process with name %s' % moduleName)
        else:
            print('Module32First is False %s' % GetLastError())
            CloseHandle(hModuleSnap)


def GetModuleSnap(ProcessId):
    me32 = MODULEENTRY32()
    me32.dwSize = sizeof(MODULEENTRY32)
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId)

    ret = Module32First(hModuleSnap, ctypes.byref(me32))

    print("ret: %d" % ret)
    if GetLastError() != 0:
        print("hModuleSnap: %d" % hModuleSnap)
        CloseHandle(hModuleSnap)
        print('Handle Error %s' % GetLastError())
        return 'Error'
    else:
        if (Module32First(hModuleSnap, pointer(me32))):
            moduleName = []
            modeleMsg = []
            moduleName.append(me32.szModule.decode())  # 这里因为是Python3，输出字符会在前面出现一个b'xxx'，所以要先使用decode解码
            moduleName.append(hex(me32.modBaseAddr))
            modeleMsg.append(moduleName)

            Module32Next(hModuleSnap, pointer(me32))
            while int(GetLastError()) != 18:
                moduleName = []
                moduleName.append(me32.szModule.decode())  # 这里因为是Python3，输出字符会在前面出现一个b'xxx'，所以要先使用decode解码
                moduleName.append(hex(me32.modBaseAddr))
                modeleMsg.append(moduleName)

                Module32Next(hModuleSnap, pointer(me32))
            CloseHandle(hModuleSnap)
            return modeleMsg
        else:
            print('Module32First is False %s' % GetLastError())
            CloseHandle(hModuleSnap)
            return 'Error'
