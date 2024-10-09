import binascii
import random
import sys
import time

from ctypes import *
import win32event
import PVZ_tools
from PVZ_tools import *
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow

import PVZ_cheat_ui
import winProcess_get32Model

PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
# PROCESS_ALL_ACCESS = 0x001F0FFF
THREAD_ALL_ACCESS = 0x001F03FF
VIRTUAL_MEM = (0x1000 | 0x2000)
MEM_RELEASE = 0x00008000

# kernel32 = windll.kernel32
kernel32 = windll.LoadLibrary("kernel32.dll")

from pynput.keyboard import Key, Listener


def on_press(key):
    # 监听按键
    print('{0} pressed'.format(key))


def on_release(key):
    # 监听释放
    print('{0} release'.format(key))
    if key == Key.f4:
        call_Bullet()
    if key == Key.f5:
        # rend_plant()
        run_harvest()
    if key == Key.f3:
        # Stop listener
        call_killZombie()
        # return False
    if key == Key.up:
        plant_move(0, -1)
    if key == Key.down:
        plant_move(0, 1)
    if key == Key.left:
        plant_move(1, 0)
    if key == Key.right:
        plant_move(1, 0)


class keyThread(QThread):
    def __init__(self):
        super(keyThread, self).__init__()

    def run(self):
        # 连接事件以及释放
        with Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()


def inject_autoplant(hProcess, data):
    # hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
    # print("hProcess: %s" % hProcess)
    # if not hProcess:
    #     print("[*] Couldn't acquire a handle to PID: %s" % pid)
    autoplant_address = kernel32.VirtualAllocEx(hProcess, 0, 1000, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    num = 4294967296 + data[1] - autoplant_address - 5 - 20  # 计算跳转地址距离
    print("%X" % num)

    call_addr = Deal_Addr(num)
    ecx_addr = data[0]
    d1 = '608B0D'
    d2 = '6AFF6A' + ui.lineEdit_Plant.text() + 'C7C0' + ui.lineEdit_Y.text() + '0000006A' + ui.lineEdit_X.text() + '51E8'
    d3 = '61C3'
    d = d1 + ecx_addr + d2 + call_addr + d3
    data = binascii.a2b_hex(d)
    print(data)
    print(len(data))
    print("arg_address: %X" % autoplant_address)

    written = c_int(0)
    kernel32.WriteProcessMemory(hProcess, autoplant_address, data, len(data), byref(written))
    print("written: %s" % written)

    thread_id = c_ulong(0)
    if not kernel32.CreateRemoteThread(hProcess, None, 0, autoplant_address, 0, 0, byref(thread_id)):
        print("[*] Failed to inject the DLL. Exiting.")
        sys.exit(0)
    print("thread_id: %s" % thread_id)
    h_Thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, int(thread_id.value))
    print(h_Thread)
    kernel32.WaitForSingleObject(h_Thread, win32event.INFINITE)  # 等待，直到线程被激发
    kernel32.CloseHandle(h_Thread)
    kernel32.VirtualFreeEx(hProcess, autoplant_address, 0, MEM_RELEASE)  # 释放内存

    return True


# 读取阳光数量
def get_sun():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print(ModuleBaseAddr)
    # print("0x%X" % int(ModuleBaseAddr))
    #
    addr = GetValue(hProcess, ModuleBaseAddr + 0x355E0C, 4)  # addr = ["GameAssembly.dll"+0166E164]
    addr = GetValue(hProcess, addr + 0x868, 4)  # addr = [addr]
    addr = GetValue(hProcess, addr + 0x5578, 4)  # addr = [addr + 0x70]

    print("%d" % addr)  # SLP瓶指针

    kernel32.CloseHandle(hProcess)
    return addr


def flash_sun():
    ui.lineEdit_sun.setText(str(get_sun()))


# 设置阳光数量
def set_sun():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)

    addr = GetValue(hProcess, ModuleBaseAddr + 0x355E0C, 4)  # addr = ["GameAssembly.dll"+0166E164]
    addr = GetValue(hProcess, addr + 0x868, 4)  # addr = [addr + 0x868]
    # addr = GetValue(hProcess, addr + 0x5578, 4)  # addr = [addr + 0x5578]
    newdata = ui.lineEdit_sun.text()

    if not newdata.isdigit():
        kernel32.CloseHandle(hProcess)
        return
    SetValue(hProcess, addr + 0x5578, newdata, 4)

    kernel32.CloseHandle(hProcess)


# 自动收集阳光
def colloct_sun():
    # PlantsVsZombies.exe+3CC6E - 80 7B 50 01           - cmp byte ptr [ebx+50],01
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)
    if ui.checkBox_CollectSun.isChecked():
        SetValue(hProcess, ModuleBaseAddr + 0x3CC6E, 0x01507B80, 4)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x3CC6E, 0x00507B80, 4)
    kernel32.CloseHandle(hProcess)


# 发射标志
def shoot_flag():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)
    if ui.checkBox_shoot.isChecked():
        SetValue(hProcess, ModuleBaseAddr + 0x72EE4, 0x840F, 2)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x72EE4, 0x850F, 2)

    kernel32.CloseHandle(hProcess)


# 取消冷却进度
def set_cooling():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)

    addr = GetValue(hProcess, ModuleBaseAddr + 0x12A404, 4)  # addr = ["GameAssembly.dll"+0166E164]
    addr = GetValue(hProcess, addr + 0x90, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x2C, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x20, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x15C, 4)  # addr = [addr + 0x868]

    # addr = GetValue(hProcess, addr + 0x5578, 4)  # addr = [addr + 0x5578]
    for i in range(0, 10):
        if GetValue(hProcess, addr + 0x4C + i * 0x50, 4) < 5000:
            SetValue(hProcess, addr + 0x4C + i * 0x50, 5000, 4)
    kernel32.CloseHandle(hProcess)


# 取消冷却标志位
def set_cooling_flag():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)

    addr = GetValue(hProcess, ModuleBaseAddr + 0x12A404, 4)  # addr = ["GameAssembly.dll"+0166E164]
    addr = GetValue(hProcess, addr + 0x90, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x2C, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x20, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x15C, 4)  # addr = [addr + 0x868]

    # data = GetValue(hProcess, addr + 0x5578, 4)  # addr = [addr + 0x5578]
    for i in range(0, 10):
        data = GetValue(hProcess, addr + 0x4C + i * 0x50 + 0x24, 2)
        # print(data)
        if data == 256 or data == 0:
            SetValue(hProcess, addr + 0x4C + i * 0x50 + 0x24, 0x1, 2)
    kernel32.CloseHandle(hProcess)


# 后台运行，不停止
def set_backruning():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    if ui.checkBox_backruning.isChecked():
        SetValue(hProcess, ModuleBaseAddr + 0x2127B, 0x37EB, 2)
        SetValue(hProcess, ModuleBaseAddr + 0x129A20, 0xC39090C3, 4)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x2127B, 0x3774, 2)
        SetValue(hProcess, ModuleBaseAddr + 0x129A20, 0xC31C408B, 4)
    kernel32.CloseHandle(hProcess)


# 更改卡槽植物
def change_plant():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)

    addr = GetValue(hProcess, ModuleBaseAddr + 0x12A404, 4)  # addr = ["GameAssembly.dll"+0166E164]
    addr = GetValue(hProcess, addr + 0x90, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x2C, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x20, 4)  # addr = [addr + 0x868]
    addr = GetValue(hProcess, addr + 0x15C, 4)  # addr = [addr + 0x868]

    # data = GetValue(hProcess, addr + 0x5578, 4)  # addr = [addr + 0x5578]
    i = int(ui.lineEdit_Kid.text())
    p = int(ui.lineEdit_Pid.text())
    SetValue(hProcess, addr + 0x4C + i * 0x50 + 0x10, p, 1)
    kernel32.CloseHandle(hProcess)


# 种植不扣除阳光
def no_sun():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)

    # GetValue(hProcess, ModuleBaseAddr + 0x27694, 2)
    if ui.checkBox_nosun.isChecked():
        SetValue(hProcess, ModuleBaseAddr + 0x27694, 0x9090, 2)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x27694, 0xF32B, 2)

    # GetValue(hProcess, ModuleBaseAddr + 0x27694, 2)
    kernel32.CloseHandle(hProcess)


# 重复种植 0041BD2D  - 0F84 46090090    je 9041C679 ; 判断重复种植
def set_replant():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    print("0x%X" % ModuleBaseAddr)

    # GetValue(hProcess, ModuleBaseAddr + 0x27694, 2)
    if ui.checkBox_replant.isChecked():
        SetValue(hProcess, ModuleBaseAddr + 0x1BD2D, 0x9090000947E9, 6)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x1BD2D, 0x90000946840F, 6)
    kernel32.CloseHandle(hProcess)


# 自动种植call
def call_autoplant():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    ecx_addr = GetValue(hProcess, ModuleBaseAddr + 0x355E0C, 4) + 0x868
    call_addr = ModuleBaseAddr + 0x18D70

    print("%X" % ecx_addr)
    print("0x%X" % call_addr)

    ecx_addr = Deal_Addr(ecx_addr)

    code = [ecx_addr, call_addr]
    print(code)

    inject_autoplant(hProcess, code)  # 注入线程代码
    kernel32.CloseHandle(hProcess)


# 僵尸种植call
def call_zombie():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    data = "60 8B 15 0C 5E 35 00 8B 92 68 08 00 00 8B 92 78 01 00 00 6A 08 6A 06 C7 C0 02 00 00 00 8B CA E8 8B 53 C3 FF 61 C3"
    ecx_addr = ModuleBaseAddr + 0x355E0C
    call_addr = ModuleBaseAddr + 0x35390

    print("%X" % ecx_addr)
    print("0x%X" % call_addr)

    code = [data, ecx_addr, call_addr]
    print(code)

    inject_zombie(hProcess, code)  # 注入线程代码
    kernel32.CloseHandle(hProcess)


def inject_zombie(hProcess, code):
    data = code[0]
    s = data.split(" ")
    data = ""
    for i in range(0, len(s)):
        data = data + s[i]
    print(data)
    callzombie_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    num = code[2] - (callzombie_address + len(s) - 2)  # 计算跳转地址距离
    print("%X" % num)
    call_addr = Deal_Addr(num)
    ecx_addr = Deal_Addr(code[1])
    data = data.replace('8B53C3FF', call_addr)
    data = data.replace('0C5E3500', ecx_addr)
    data = data.replace('6A08', '6A' + ui.lineEdit_ZX.text())
    data = data.replace('6A06', '6A' + ui.lineEdit_Zombie.text())
    data = data.replace('C7C002', 'C7C0' + ui.lineEdit_ZY.text())
    data = binascii.a2b_hex(data)

    print("callzombie_address: %X" % callzombie_address)

    written = c_int(0)
    kernel32.WriteProcessMemory(hProcess, callzombie_address, data, len(data), byref(written))
    print("written: %s" % written)

    thread_id = c_ulong(0)
    if not kernel32.CreateRemoteThread(hProcess, None, 0, callzombie_address, 0, 0, byref(thread_id)):
        print("[*] Failed to inject the DLL. Exiting.")
        sys.exit(0)
    print("thread_id: %s" % thread_id)
    # 释放线程
    h_Thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, int(thread_id.value))
    print(h_Thread)
    kernel32.WaitForSingleObject(h_Thread, win32event.INFINITE)  # 等待，直到线程被激发
    kernel32.CloseHandle(h_Thread)
    kernel32.VirtualFreeEx(hProcess, callzombie_address, 0, MEM_RELEASE)  # 释放内存

    return True


# 秒杀僵尸
def call_killZombie():
    global zombie_state_address

    if zombie_state_address == '':
        return
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    print(hex(zombie_state_address + 0x4))
    print(hProcess, GetValue(hProcess, zombie_state_address, 4))
    num = ui.lineEdit_zombie_State.text()
    if not num.isdigit():
        return
    for i in range(0, int(num)):
        SetValue(hProcess, GetValue(hProcess, zombie_state_address, 4) + 0x4, 3, 4)
        time.sleep(0.1)
    kernel32.CloseHandle(hProcess)


# 僵尸状态人造变量
def call_Zombie_state():
    global zombie_address
    global zombie_state_address
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        return
    if ui.checkBox_zombie_State.isChecked():
        call_addr = ModuleBaseAddr + 0x149848

        data = "60 8D 41 24 A3 00 08 85 00 61 8B 41 24 83 F8 0E E9 38 98 BC FF"
        s = data.split(" ")

        zombie_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        print("zombie_address: %X" % zombie_address)  # 申请代码注入内存

        zombie_state_address = kernel32.VirtualAllocEx(hProcess, 0, 5, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        print("zombie_state_address: %X" % zombie_state_address)  # 申请人造变量

        data = ""
        for i in range(0, len(s)):
            data = data + s[i]
        # 替换跳转距离
        # num = 4294967296 + call_addr - zombie_address + 5 - len(s)  # 回跳距离
        num = (call_addr + 5) - (zombie_address + len(s))  # 回跳距离（兜一圈）
        a = "%X" % num
        print("num: ", a)
        jmp_back = Deal_Addr(num)
        data = data[0:-8] + jmp_back
        # 替换人造变量地址
        b = Deal_Addr(zombie_state_address)
        print(b)
        data = data.replace('00088500', b)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        written = c_int(0)
        kernel32.WriteProcessMemory(hProcess, zombie_address, data, len(data), byref(written))
        print("written: %s" % written)
        # 注入秒杀跳转地址
        num = zombie_address - (ModuleBaseAddr + 0x149848) - 5
        print(num)
        jmp_forward = Deal_Addr(num)
        data = 'E9' + jmp_forward + '90'
        print(data)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        kernel32.WriteProcessMemory(hProcess, ModuleBaseAddr + 0x149848, data, len(data), None)
        ui.lineEdit_zombie_State.setText('5')
        thread_key.start()
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x149848, 0x0EF88324418B, 6)
        kernel32.VirtualFreeEx(hProcess, zombie_address, 0, MEM_RELEASE)  # 释放内存
        kernel32.VirtualFreeEx(hProcess, zombie_state_address, 0, MEM_RELEASE)  # 释放内存
        zombie_state_address = ''
    kernel32.CloseHandle(hProcess)


def ran_bullet():
    call_Bullet_state()
    PVZ_Thread()


# 随机子弹
def call_Bullet():
    global Bullet_zombie_state_address

    if Bullet_zombie_state_address == '':
        print("return")
        return

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    print(hex(Bullet_zombie_state_address + 0x5C))
    print(hProcess, GetValue(hProcess, Bullet_zombie_state_address, 4))
    SetValue(hProcess, GetValue(hProcess, Bullet_zombie_state_address, 4) + 0x5C, random.randint(0, 13), 4)

    kernel32.CloseHandle(hProcess)


# 子弹状态人造变量
def call_Bullet_state():
    global Bullet_address
    global Bullet_zombie_state_address

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    if ui.checkBox_bullet.isChecked():
        call_addr = ModuleBaseAddr + 0x7D14A  # 修改JMP代码位置

        data = "60 8B C7 A3 00 08 B1 00 61 8B 77 5C B3 01 E9 3C D1 96 FF"
        s = data.split(" ")

        Bullet_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        print("Bullet_address: %X" % Bullet_address)  # 申请代码注入内存
        # MEM_RELEASE = 0x00008000
        # kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)

        Bullet_zombie_state_address = kernel32.VirtualAllocEx(hProcess, 0, 5, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        print("zombie_state_address: %X" % Bullet_zombie_state_address)  # 申请人造变量

        data = ""
        for i in range(0, len(s)):
            data = data + s[i]
        # 替换跳转距离
        # num = 4294967296 + call_addr - zombie_address + 5 - len(s)  # 回跳距离
        num = (call_addr + 5) - (Bullet_address + len(s))  # 回跳距离（兜一圈）
        a = "%X" % num
        print("num: ", a)
        jmp_back = Deal_Addr(num)
        data = data[0:-8] + jmp_back
        # 替换人造变量地址
        b = Deal_Addr(Bullet_zombie_state_address)
        print(b)
        data = data.replace('0008B100', b)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        written = c_int(0)
        kernel32.WriteProcessMemory(hProcess, Bullet_address, data, len(data), byref(written))
        print("written: %s" % written)
        # 注入秒杀跳转地址
        num = Bullet_address - (ModuleBaseAddr + 0x7D14A) - 5
        print(num)
        jmp_forward = Deal_Addr(num)
        print(jmp_forward)
        data = 'E9' + jmp_forward
        print(data)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        kernel32.WriteProcessMemory(hProcess, call_addr, data, len(data), None)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x7D14A, 0x01B35C778B, 5)
        kernel32.VirtualFreeEx(hProcess, Bullet_address, 0, MEM_RELEASE)  # 释放内存
        kernel32.VirtualFreeEx(hProcess, Bullet_zombie_state_address, 0, MEM_RELEASE)  # 释放内存
        Bullet_zombie_state_address = ''
    kernel32.CloseHandle(hProcess)


# 设置玉米炮弹状态
def set_Bullet_state():
    global Bullet_address
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    call_addr = ModuleBaseAddr + 0x7BB69  # 修改JMP代码位置
    if ui.checkBox_bullet.isChecked():
        data = "C7 45 5C 0B 00 00 00 8B C6 E9 60 BB 2B 00"
        s = data.split(" ")

        Bullet_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        print("zombie_address: %X" % Bullet_address)  # 申请代码注入内存
        # MEM_RELEASE = 0x00008000
        # kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)

        data = ""
        for i in range(0, len(s)):
            data = data + s[i]
        # 替换跳转距离
        num = (call_addr + 5) - (Bullet_address + len(s))  # 回跳距离（兜一圈）
        a = "%X" % num
        print("num: ", a)
        jmp_back = Deal_Addr(num)
        data = data[0:-8] + jmp_back
        bullet = ui.lineEdit_bullet.text()
        if not bullet.isdigit():
            return
        bullet = int(bullet)
        if 0 > bullet or bullet > 13:
            bullet = 11
        print("0%X" % bullet)
        data = data.replace('0B000000', "0%X000000" % bullet)
        print(data)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        written = c_int(0)
        kernel32.WriteProcessMemory(hProcess, Bullet_address, data, len(data), byref(written))
        print("written: %s" % written)
        # 注入秒杀跳转地址
        num = Bullet_address - (call_addr + 5)
        jmp_forward = Deal_Addr(num)
        print(jmp_forward)
        data = 'E9' + jmp_forward
        print(data)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        kernel32.WriteProcessMemory(hProcess, call_addr, data, len(data), None)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x7BB69, 0xC68B5C4589, 5)
        kernel32.VirtualFreeEx(hProcess, Bullet_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(hProcess)


# 设置陶瓷瓶罐透视状态
def set_jug_state():
    global jug_address
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    call_addr = ModuleBaseAddr + 0x59214  # 修改JMP代码位置
    jng_addr = ModuleBaseAddr + 0x59553  # jng 地址
    if ui.checkBox_jug.isChecked():
        # data = "C7 45 4C 32 00 00 00 83 7D 4C 00 E9 08 92 F5 EE"
        data = "C7 45 4C 32 00 00 00 83 7D 4C 00 0F 8E 42 95 BE FF E9 08 92 BE FF"
        s = data.split(" ")

        jug_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        print("jug_address: %X" % jug_address)  # 申请代码注入内存
        # MEM_RELEASE = 0x00008000
        # kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)

        data = ""
        for i in range(0, len(s)):
            data = data + s[i]
        # 替换跳转距离
        num = (call_addr + 10) - (jug_address + len(s))  # 回跳距离（兜一圈）
        a = "%X" % num
        print("num: ", a)
        jmp_back = Deal_Addr(num)
        data = data[0:-8] + jmp_back

        jng_num = (jng_addr + 5) - (jug_address + len(s))  # 回跳距离（兜一圈）
        jng_back = Deal_Addr(jng_num)
        data = data.replace('4295BEFF', jng_back)
        print(data)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        written = c_int(0)
        kernel32.WriteProcessMemory(hProcess, jug_address, data, len(data), byref(written))
        print("written: %s" % written)
        # 注入秒杀跳转地址
        num = jug_address - (call_addr + 5)
        jmp_forward = Deal_Addr(num)
        print(jmp_forward)
        data = 'E9' + jmp_forward
        print(data)
        data = binascii.a2b_hex(data)  # 第一种 shellcode 转换
        kernel32.WriteProcessMemory(hProcess, call_addr, data, len(data), None)
    else:
        SetValue(hProcess, call_addr, 0x0f004c7d83, 5)
        kernel32.VirtualFreeEx(hProcess, jug_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(hProcess)


# 设置传送带无延迟
def set_belt_state():
    global card_address  # 卡片速度
    global card_call_addr  # 卡片速度跳转
    global belt_address  # 传送带速度
    global belt_call_addr  # 传送带速度跳转

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    if ui.checkBox_belt.isChecked():
        data = "83 43 5C B0 83 7B 5C 00 E9 81 E5 26 00"
        card_call_addr = ModuleBaseAddr + 0x2E587  # 修改JMP代码位置
        card_call_num = 7
        card_address = PVZ_tools.inject_code(hProcess, data, card_call_addr, card_call_num)

        data = "C7 86 4C 03 00 00 00 00 00 00 E9 C7 F6 B1 FF"
        belt_call_addr = ModuleBaseAddr + 0x9F6D0  # 修改JMP代码位置
        belt_call_num = 6
        belt_address = PVZ_tools.inject_code(hProcess, data, belt_call_addr, belt_call_num)
    else:
        SetValue(hProcess, card_call_addr, 0x7B835C4BFF, 5)
        kernel32.VirtualFreeEx(hProcess, card_address, 0, MEM_RELEASE)

        SetValue(hProcess, belt_call_addr, 0x0000034C86FF, 5)
        kernel32.VirtualFreeEx(hProcess, belt_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(hProcess)


# 竖列种植
def col_plant():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    if ui.checkBox_column.isChecked():
        SetValue(hProcess, ModuleBaseAddr + 0x1CA0F, 0x909090909090, 6)
    else:
        SetValue(hProcess, ModuleBaseAddr + 0x1CA0F, 0x000000F8850F, 6)
    kernel32.CloseHandle(hProcess)


# 取得僵尸ID地址
def get_zombies():
    global zombies_addr
    global zombies_address
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    zombies_addr = ModuleBaseAddr + 0x149741  # 修改JMP代码位置
    zombies_num = 7
    if ui.checkBox_harvester.isChecked():
        data = "89 0D 00 08 92 00 D9 41 2C 57 DA 61 08 E9 36 97 C2 FF"  # 注入的代码
        _var = '00089200'  # 人造变量地址
        zombies_address = PVZ_tools.inject_code(hProcess, data, zombies_addr, zombies_num, _var)

    else:
        SetValue(hProcess, zombies_addr, 0x0861DA572C41D9, zombies_num)
        kernel32.VirtualFreeEx(hProcess, zombies_address['arg_address'], 0, MEM_RELEASE)
        kernel32.VirtualFreeEx(hProcess, zombies_address['zombie_state_address'], 0, MEM_RELEASE)
    # return zombies_address['zombie_state_address']

    kernel32.CloseHandle(hProcess)


# 取得推车ID地址
def get_harvests():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    harvests = []
    addr = GetValue(hProcess, ModuleBaseAddr + 0x355E0C, 4)
    addr = GetValue(hProcess, addr + 0x868, 4)
    harvest = GetValue(hProcess, addr + 0x118, 4)
    kernel32.CloseHandle(hProcess)
    for i in range(0, 5):
        harvests.append(harvest + (i * 0x48))
    print(harvests)
    return harvests


def run_harvest():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    calladdr = ModuleBaseAddr + 0x66490
    zombies = zombies_address['zombie_state_address']
    print("僵尸ID: %X" % zombies)
    if zombies == 0:
        kernel32.CloseHandle(hProcess)
        return
    time.sleep(0.1)
    zombies = GetValue(hProcess, zombies, 4)
    print("僵尸ID: %X" % zombies)
    zombies = Deal_Addr(zombies)
    harvest = get_harvests()
    if harvest == 0:
        kernel32.CloseHandle(hProcess)
        return
    harvest = Deal_Addr(harvest)
    data = '60 68 80 11 9D 28 B8 20 FB 38 28 E8 80 64 2A 00 61 C3'
    s = data.split(" ")
    # 申请内存
    arg_address = kernel32.VirtualAllocEx(hProcess, 0, len(s), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    print("arg_address: %X" % arg_address)
    data = ""
    for i in range(0, len(s)):
        data = data + s[i]
    data = data.replace('80119D28', zombies)
    data = data.replace('20FB3828', harvest)

    num = Deal_Addr(calladdr - (arg_address + len(s) - 2))
    data = data.replace('80642A00', num)
    data = binascii.a2b_hex(data)

    # 注入代码写入内存
    written = c_int(0)
    kernel32.WriteProcessMemory(hProcess, arg_address, data, len(data), byref(written))
    print("written: %s" % written)

    # 执行远程线程
    thread_id = c_ulong(0)
    if not kernel32.CreateRemoteThread(hProcess, None, 0, arg_address, 0, 0, byref(thread_id)):
        print("[*] Failed to inject the DLL. Exiting.")
        sys.exit(0)
    print("thread_id: %s" % thread_id)
    h_Thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, int(thread_id.value))
    print(h_Thread)
    kernel32.WaitForSingleObject(h_Thread, win32event.INFINITE)  # 等待，直到线程被激发
    kernel32.CloseHandle(h_Thread)
    kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)  # 释放内存

    kernel32.CloseHandle(hProcess)
    return True


# 指定植物种植_方法1
def ren_plant():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    addr = GetValue(hProcess, ModuleBaseAddr + 0x355E0C, 4)
    addr = GetValue(hProcess, addr + 0x868, 4)
    addr = GetValue(hProcess, addr + 0x150, 4)
    GetValue(hProcess, addr + 0x28, 4)

    SetValue(hProcess, addr + 0x28, 0x16, 4)

    kernel32.CloseHandle(hProcess)
    return True


# 指定植物种植_方法2
def rend_plant():
    global r_plant_address

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    call_addr = ModuleBaseAddr + 0x1C9B1
    call_num = 7
    if ui.checkBox_ranplant.isChecked():
        data = 'B8 15 00 00 00 8B 4C 24 0C E9 AA C9 25 00'
        d = ui.lineEdit_Plant.text()
        if not d.isdigit():
            kernel32.CloseHandle(hProcess)
            return
        d = '0' + d
        d = d[-2:]
        data = data.replace('15', d)

        if r_plant_address['arg_address'] != 0:
            kernel32.VirtualFreeEx(hProcess, r_plant_address['arg_address'], 0, MEM_RELEASE)  # 释放内存
        r_plant_address = PVZ_tools.inject_code(hProcess, data, call_addr, call_num)
    else:
        kernel32.VirtualFreeEx(hProcess, r_plant_address['arg_address'], 0, MEM_RELEASE)
        SetValue(hProcess, call_addr, 0x0C244C8B28408B, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 小推车不消失
def harvester_alive():
    global r_plant_address

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    call_addr = ModuleBaseAddr + 0x66C6A
    call_num = 4
    call_addr1 = ModuleBaseAddr + 0x327A78
    print("call_addr1: %X" % call_addr1)
    call_num1 = 4
    if ui.checkBox_harvester_alive.isChecked():
        # 让推车永不消失
        data = 0x003047C6
        SetValue(hProcess, call_addr, data, call_num)
        SetValue(hProcess, call_addr1, 0xC1A00000, call_num1)

        # 调用恢复推车 CALL
        data = '60 68 50 D4 D4 28 B8 02 00 00 00 E8 50 5F 86 FF 61 C3'
        call_addr = ModuleBaseAddr + 0x65F60
        num = get_harvests()
        for i in range(0, len(num)):
            d = "%X" % num[i]
            d1 = ''
            for j in range(0, len(d), 2):
                d1 = d[j:j + 2] + ' ' + d1
            d1 = d1 + "B8 0%d" % i
            data = data.replace('50 D4 D4 28 B8 02', d1)
            print(data)
            PVZ_tools.inject_runcode(hProcess, data, call_addr)
            data = '60 68 50 D4 D4 28 B8 02 00 00 00 E8 50 5F 86 FF 61 C3'

    else:
        data = 0x013047C6
        SetValue(hProcess, call_addr, data, call_num)

    kernel32.CloseHandle(hProcess)
    return True


def harvester_run():
    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return

    call_addr = ModuleBaseAddr + 0x66C6A
    call_num = 4
    call_addr1 = ModuleBaseAddr + 0x327A78
    print("call_addr1: %X" % call_addr1)
    call_num1 = 4
    if ui.checkBox_harvester_alive.isChecked():
        # 让推车永不消失
        data = 0x003047C6
        SetValue(hProcess, call_addr, data, call_num)
        SetValue(hProcess, call_addr1, 0xC1A00000, call_num1)

        # 调用恢复推车 CALL
        data = '60 BE 10 F3 F0 27 E8 E5 6C AE FF 61 C3'
        call_addr = ModuleBaseAddr + 0x66CF0
        num = get_harvests()
        for i in range(0, len(num)):
            d = "%X" % num[i]
            d1 = ''
            for j in range(0, len(d), 2):
                d1 = d[j:j + 2] + ' ' + d1

            data = data.replace('10 F3 F0 27 ', d1)
            print(data)
            PVZ_tools.inject_runcode(hProcess, data, call_addr)
            data = '60 BE 10 F3 F0 27 E8 E5 6C AE FF 61 C3'
    else:
        data = 0x013047C6
        SetValue(hProcess, call_addr, data, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 僵尸0秒出动
def zombies_zero():
    global zombies_zero_address

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    jmp_addr = ModuleBaseAddr + 0x1FF1C
    call_num = 6
    if ui.checkBox_zombies_zero.isChecked():
        data = 'C7 85 B4 55 00 00 01 00 00 00 FF 8D B4 55 00 00 E9 0D FF 24 00'
        zombies_zero_address = PVZ_tools.inject_code(hProcess, data, jmp_addr, call_num)
    else:
        kernel32.VirtualFreeEx(hProcess, zombies_zero_address['arg_address'], 0, MEM_RELEASE)
        SetValue(hProcess, jmp_addr, 0x000055B48DFF, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 清除墓碑
def tomb_clean():
    global zombies_zero_address

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    set_addr = ModuleBaseAddr + 0x27A39
    call_num = 2
    if ui.checkBox_tomb_clean.isChecked():
        SetValue(hProcess, set_addr, 0x9090, call_num)
    else:
        SetValue(hProcess, set_addr, 0x9674, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 清除植物
def plant_clean():
    global zombies_zero_address

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    set_addr = ModuleBaseAddr + 0x2774E
    call_num = 2
    if ui.checkBox_plant_clean.isChecked():
        SetValue(hProcess, set_addr, 0x9090, call_num)
    else:
        SetValue(hProcess, set_addr, 0xB074, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 移动植物
def plant_move(x, y):
    global zombies_zero_address

    ProcessId = winProcess_get32Model._GetProcessId(None, u"Plants vs. Zombies")
    if ProcessId == 0:
        return

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    print("hProcess: %s" % hProcess)
    if not hProcess:
        print("[*] Couldn't acquire a handle to PID: %s" % ProcessId)
        return

    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(ProcessId, "PlantsVsZombies.exe")
    if ModuleBaseAddr == 0:
        kernel32.CloseHandle(hProcess)
        return
    addr = ModuleBaseAddr + 0x355E0C
    call_num = 2
    if ui.checkBox_plant_move.isChecked():
        addr = GetValue(hProcess, addr + 0x868, 4)
        addr = GetValue(hProcess, addr + 0xc4, 4)

        p_x = GetValue(hProcess, addr + 0x8, 4)
        p_x = GetValue(hProcess, p_x, 4)
        SetValue(hProcess, addr, p_x + x * 80, call_num)

        p_y = GetValue(hProcess, addr + 0x8 + 0x4, 4)
        p_y = GetValue(hProcess, p_y, 4)
        SetValue(hProcess, addr, p_y + y * 100, call_num)

        m_x = GetValue(hProcess, addr + 0x8 + 0x20, 4)
        m_x = GetValue(hProcess, m_x, 4)
        SetValue(hProcess, addr, m_x + x, call_num)

        m_y = GetValue(hProcess, addr + 0x8 + 0x4 + 0x20, 4)
        m_y = GetValue(hProcess, m_y, 4)
        SetValue(hProcess, addr, m_y + y, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 食人花无冷却
def plant_eat():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']
    addr = ModuleBaseAddr + 0x6F925
    call_num = 2
    if ui.checkBox_plant_eat.isChecked():
        SetValue(hProcess, addr, 0x9090, call_num)
    else:
        SetValue(hProcess, addr, 0x5f75, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 地雷无冷却
def plant_bomb():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']
    addr = ModuleBaseAddr + 0x6E223
    call_num = 6
    if ui.checkBox_plant_bomb.isChecked():
        SetValue(hProcess, addr, 0x909090909090, call_num)
    else:
        SetValue(hProcess, addr, 0x000001FD850F, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 加农炮无冷却
def plant_canon():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']
    addr = ModuleBaseAddr + 0x6F40A
    call_num = 6
    print("ok~~")
    if ui.checkBox_plant_cannon.isChecked():
        SetValue(hProcess, addr, 0x909090909090, call_num)
    else:
        SetValue(hProcess, addr, 0x00000192850F, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 磁力菇无冷却
def plant_magnetic():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']
    addr = ModuleBaseAddr + 0x70216
    call_num = 6
    if ui.checkBox_plant_magnetic.isChecked():
        SetValue(hProcess, addr, 0x909090909090, call_num)
    else:
        SetValue(hProcess, addr, 0x00000546850F, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 僵尸冰道消除
def zombie_ice():
    global zombie_ice_addr
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']

    jmp_addr = ModuleBaseAddr + 0x2021F
    call_num = 10
    if ui.checkBox_no_snow.isChecked():
        data = 'BF 00 00 00 00 89 7D 00 8B 83 A4 00 00 00 E9 16 02 A5 FF'
        zombie_ice_addr = inject_code(hProcess, data, jmp_addr, call_num, _var='')
    else:
        SetValue(hProcess, jmp_addr, 0x8B007D894F, 5)
        kernel32.VirtualFreeEx(hProcess, zombie_ice_addr['arg_address'], 0, MEM_RELEASE)

    kernel32.CloseHandle(hProcess)
    return True


# 脆皮僵尸，一击
def zombies_kill():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']
    addr = ModuleBaseAddr + 0x14D52C
    addr1 = ModuleBaseAddr + 0x14CDF6
    call_num = 2
    if ui.checkBox_zombie_kill.isChecked():
        SetValue(hProcess, addr, 0x9090, call_num)
        SetValue(hProcess, addr1, 0x9090, call_num)
    else:
        SetValue(hProcess, addr, 0x1D7F, call_num)
        SetValue(hProcess, addr1, 0x1175, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 僵尸数量初始化
def zombies_build():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']
    addr = ModuleBaseAddr + 0x45D32  # 僵尸生成跳转
    call_num = 6
    SetValue(hProcess, addr, 0x909090909090, call_num)
    data = '60 8B 35 0C 5E 75 00 8B B6 68 08 00 00 8B B6 74 01 00 00 56 E8 07 5D 7C FF 61 C3'
    esi_addr = ModuleBaseAddr + 0x355E0C
    esi = PVZ_tools.get_esi(hProcess, esi_addr)
    data = data.replace('0C 5E 75 00 ', esi)
    print(data)
    call_addr = ModuleBaseAddr + 0x45D20
    PVZ_tools.inject_runcode(hProcess, data, call_addr)

    SetValue(hProcess, addr, 0x00000584850F, call_num)

    kernel32.CloseHandle(hProcess)
    return True


# 设置肥料数量
def set_manure():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']

    addr = ModuleBaseAddr + 0x355E0C  # 僵尸生成跳转
    addr = GetValue(hProcess, addr, 4)
    addr = GetValue(hProcess, addr + 0x950, 4)
    GetValue(hProcess, addr + 0x220, 4)

    num = ui.lineEdit_manure.text()
    if num.isdigit():
        num = int(num) + 1000
        SetValue(hProcess, addr + 0x220, num, 4)


# 设置喷壶数量
def set_wateringpot():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']

    offset_list = [0x355E0C, 0x950]
    addr = get_base(hProcess, ModuleBaseAddr, offset_list, num=4)

    num = ui.lineEdit_wateringpot.text()
    if num.isdigit():
        num = int(num) + 1000
        SetValue(hProcess, addr + 0x224, num, 4)


# 设置巧克力数量
def set_chocolate():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']

    offset_list = [0x355E0C, 0x950]
    addr = get_base(hProcess, ModuleBaseAddr, offset_list, num=4)

    num = ui.lineEdit_chocolate.text()
    if num.isdigit():
        num = int(num) + 1000
        SetValue(hProcess, addr + 0x250, num, 4)


# 设置树肥数量
def set_treefertilizer():
    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']

    offset_list = [0x355E0C, 0x950]
    addr = get_base(hProcess, ModuleBaseAddr, offset_list, num=4)

    num = ui.lineEdit_TreeFertilizer.text()
    if num.isdigit():
        num = int(num) + 1000
        SetValue(hProcess, addr + 0x258, num, 4)


# 清除浓雾
def clear_fog():
    global clear_fog_address

    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']

    jmp_addr = ModuleBaseAddr + 0x26173
    call_num = 5
    if ui.checkBox_clearfog.isChecked():
        data = 'BA 00 00 00 00 89 11 83 C1 04 E9 69 61 99 FF'
        call_num = 5
        clear_fog_address = inject_code(hProcess, data, jmp_addr, call_num)
    else:
        kernel32.VirtualFreeEx(hProcess, clear_fog_address['arg_address'], 0, MEM_RELEASE)
        SetValue(hProcess, jmp_addr, 0x04C1831189, call_num)


# 坚果变窝瓜
def nts_change():
    global nts_address

    process_name = "Plants vs. Zombies"
    module_name = "PlantsVsZombies.exe"
    process = PVZ_tools.get_process(process_name, module_name)

    if process == False:
        return

    hProcess = process['hProcess']
    ModuleBaseAddr = process['ModuleBaseAddr']

    jmp_addr = ModuleBaseAddr + 0x14BA6A
    call_num = 7
    if ui.checkBox_change.isChecked():
        data = '83 46 40 FC 8B 4E 40 83 7E 24 03 75 1C 0F 1F 40 00 81 7E 40 F4 01 00 00 77 0F 0F 1F 40 00 50 8D 46 24 C7 00 11 00 00 00 58 E9 43 BA 38 00'
        nts_address = inject_code(hProcess, data, jmp_addr, call_num)
    else:
        kernel32.VirtualFreeEx(hProcess, nts_address['arg_address'], 0, MEM_RELEASE)
        SetValue(hProcess, jmp_addr, 0x404E8BFC404683, call_num)

def PVZ_Thread():
    thread_pvz.run_flg = True
    thread_pvz.start()


def PVZ_signal_accept():
    if ui.checkBox_sun.isChecked():
        set_sun()
    if ui.checkBox_cooling.isChecked():
        set_cooling()
    if ui.checkBox_cooling_flag.isChecked():
        set_cooling_flag()
    # if ui.checkBox_bullet.isChecked():
    #     call_Bullet()


class PVZ_thread(QThread):
    _signal = pyqtSignal()  # 定义信号类型为整型

    def __init__(self):
        super(PVZ_thread, self).__init__()
        self.run_flg = False

    def run(self):
        while True:
            time.sleep(0.1)
            if not self.run_flg:
                continue
            self._signal.emit()  # 发射信号


class My_Gui(PVZ_cheat_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()

    def setupUi(self, MainWindow):
        super().setupUi(MainWindow)


def test():
    harvester_run()
    # harvester_alive()
    # get_harvests()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    MainWindow = QMainWindow()
    ui = My_Gui()
    ui.setupUi(MainWindow)
    MainWindow.show()

    global hProcess
    global zombies_address
    global r_plant_address

    thread_pvz = PVZ_thread()
    thread_pvz._signal.connect(PVZ_signal_accept)
    thread_pvz.run_flg = False

    thread_key = keyThread()  # 开启键盘监听线程

    zombies_address = {'arg_address': 0,
                       'zombie_state_address': 0}
    r_plant_address = {'arg_address': 0,
                       'zombie_state_address': 0}

    ui.lineEdit_sun.setText(str(get_sun()))

    ui.checkBox_sun.clicked.connect(PVZ_Thread)
    ui.checkBox_nosun.clicked.connect(no_sun)
    ui.checkBox_cooling.clicked.connect(PVZ_Thread)
    ui.checkBox_cooling_flag.clicked.connect(PVZ_Thread)
    ui.checkBox_CollectSun.clicked.connect(colloct_sun)
    ui.checkBox_shoot.clicked.connect(shoot_flag)
    ui.checkBox_replant.clicked.connect(set_replant)
    ui.checkBox_backruning.clicked.connect(set_backruning)
    ui.checkBox_zombie_State.clicked.connect(call_Zombie_state)
    ui.checkBox_bullet.clicked.connect(set_Bullet_state)
    ui.checkBox_jug.clicked.connect(set_jug_state)
    ui.checkBox_belt.clicked.connect(set_belt_state)
    ui.checkBox_column.clicked.connect(col_plant)
    ui.checkBox_harvester.clicked.connect(get_zombies)
    ui.checkBox_ranplant.clicked.connect(rend_plant)
    ui.checkBox_zombies_zero.clicked.connect(zombies_zero)
    ui.checkBox_tomb_clean.clicked.connect(tomb_clean)
    ui.checkBox_plant_clean.clicked.connect(plant_clean)
    ui.checkBox_plant_eat.clicked.connect(plant_eat)
    ui.checkBox_plant_bomb.clicked.connect(plant_bomb)
    ui.checkBox_plant_cannon.clicked.connect(plant_canon)
    ui.checkBox_plant_magnetic.clicked.connect(plant_magnetic)
    ui.checkBox_zombie_kill.clicked.connect(zombies_kill)
    ui.checkBox_no_snow.clicked.connect(zombie_ice)
    ui.checkBox_clearfog.clicked.connect(clear_fog)
    ui.checkBox_change.clicked.connect(nts_change)

    ui.pushButton_sun.clicked.connect(set_sun)
    ui.pushButton.clicked.connect(flash_sun)
    ui.pushButton_plant.clicked.connect(call_autoplant)
    ui.pushButton_Zombie.clicked.connect(call_zombie)
    ui.pushButton_killZombie.clicked.connect(call_killZombie)
    ui.pushButton_test.clicked.connect(test)
    ui.pushButton_harvester.clicked.connect(harvester_alive)
    ui.pushButton_harvester_run.clicked.connect(harvester_run)
    ui.pushButton_zombie_build.clicked.connect(zombies_build)
    ui.pushButton_manure.clicked.connect(set_manure)
    ui.pushButton_wateringpot.clicked.connect(set_wateringpot)
    ui.pushButton_chocolate.clicked.connect(set_chocolate)
    ui.pushButton_TreeFertilizer.clicked.connect(set_treefertilizer)

    sys.exit(app.exec_())
