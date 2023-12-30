## this file was developed by darian (not.darian) and the nce development team
import re
import time
import ctypes
import sys
import threading
import os
import json
import pymem
from colorama import init as colorama_init
from colorama import Fore, Back, Style

def compatJson(data):
    return json.dumps(data, separators=(',', ':'))

def fileCheck(file):
    if not os.path.exists(file):
        open(file, 'x')

def loadCache(cache):
    cachepath = cache + 'Cache.json'
    if os.path.exists(cachepath):
        return json.loads(open(cachepath, 'r').read())
    return {}

def saveCache(cache, data):
    cachepath = cache + 'Cache.json'
    fileCheck(cachepath)
    open(cachepath, 'w').write(compatJson(data))

colorama_init()

def removeLines(n: int = 1): # https://stackoverflow.com/questions/19596750
    while n > 0:
        n -= 1
        sys.stdout.write('\x1b[1A') # cursor up one line
        sys.stdout.write('\x1b[2K') # delete last line
    return

def close(string: str):
    input(string)
    exit()

offsets = loadCache('offsets')
if len(offsets) == 0:
    offsets = {
        'parentOffset': 0,
        'nameOffset': 0,
        'childrenOffset': 0,
    }

parentOffset = 0
nameOffset = 0
childrenOffset = 0
localPlayerOffset = 0

def updateOffset(offset, value):
    offsets.update({offset: value})
    saveCache('offsets', offsets)

## creds meow
#print(f'''                                                     
#                    ad88 88 88
#            ,d      d8"   88 ""
#            88      88    88
#8b,dPPYba,   ,adPPYba, MM88MMM MM88MMM 88 88 8b,     ,d8
#88P'   `"8a a8P_____88   88      88    88 88  `Y8, ,8P'
#88       88 8PP"""""""   88      88    88 88    )888(
#88       88 "8b,   ,aa   88,     88    88 88  ,d8" "8b,
#88       88  `"Ybbd8"'   "Y888   88    88 88 8P'     `Y8                                                   
#''')

#print(f'''                                                     
#    ___                 __                 
#__ _  __ _   / / |__  _   _  ___ / _|_ __ ___  _ __  
#/ _` |/ _` | / /| '_ \| | | |/ _ \ |_| '__/ _ \| '_ \ 
#| (_| | (_| |/ / | |_) | |_| |  __/  _| | | (_) | | | |
#(_)__, |\__, /_/  |_.__/ \__, |\___|_| |_|  \___/|_| |_|
#|___/ |___/            |___/                                                                           
#''')

class Netflix:
    def __init__(self, ProgramName=None):
        self.ProgramName = ProgramName
        self.Pymem = pymem.Pymem()
        self.Addresses = {}
        self.Handle = None
        self.is64bit = False
        self.ProcessID = None
        self.PID = self.ProcessID
        if type(ProgramName) == str:
            self.Pymem = pymem.Pymem(ProgramName)
            self.Handle = self.Pymem.process_handle
            self.is64bit = pymem.process.is_64_bit(self.Handle)
            self.ProcessID = self.Pymem.process_id
            self.PID = self.ProcessID
        elif type(ProgramName) == int:
            self.Pymem.open_process_from_id(ProgramName)
            self.Handle = self.Pymem.process_handle
            self.is64bit = pymem.process.is_64_bit(self.Handle)
            self.ProcessID = self.Pymem.process_id
            self.PID = self.ProcessID

    def h2d(self, hz: str, bit: int = 16) -> int:
        if type(hz) == int:
            return hz
        return int(hz, bit)

    def d2h(self, dc: int, UseAuto=None) -> str:
        if type(dc) == str:
            return dc
        if UseAuto:
            if UseAuto == 32:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
        else:
            if abs(dc) > 4294967295:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
        if len(dc) > 8:
            while len(dc) < 16:
                dc = "0" + dc
        if len(dc) < 8:
            while len(dc) < 8:
                dc = "0" + dc
        return dc

    def PLAT(self, aob: str):
        if type(aob) == bytes:
            return aob
        trueB = bytearray(b"")
        aob = aob.replace(" ", "")
        PLATlist = []
        for i in range(0, len(aob), 2):
            PLATlist.append(aob[i : i + 2])
        for i in PLATlist:
            if "?" in i:
                trueB.extend(b".")
            if "?" not in i:
                trueB.extend(re.escape(bytes.fromhex(i)))
        return bytes(trueB)

    def AOBSCANALL(self, AOB_HexArray, xreturn_multiple=False):
        return pymem.pattern.pattern_scan_all(
            self.Pymem.process_handle,
            self.PLAT(AOB_HexArray),
            return_multiple=xreturn_multiple,
        )

    def gethexc(self, hex: str):
        hex = hex.replace(" ", "")
        hxlist = []
        for i in range(0, len(hex), 2):
            hxlist.append(hex[i : i + 2])
        return len(hxlist)

    def hex2le(self, hex: str):
        lehex = hex.replace(" ", "")
        lelist = []
        if len(lehex) > 8:
            while len(lehex) < 16:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)
        if len(lehex) < 9:
            while len(lehex) < 8:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)

    def calcjmpop(self, des, cur):
        jmpopc = (self.h2d(des) - self.h2d(cur)) - 5
        jmpopc = hex(jmpopc & (2**32 - 1)).replace("0x", "")
        if len(jmpopc) % 2 != 0:
            jmpopc = "0" + str(jmpopc)
        return jmpopc

    def isProgramGameActive(self):
        try:
            self.Pymem.read_char(self.Pymem.base_address)
            return True
        except:
            return False

    def DRP(self, Address: int, is64Bit: bool = None) -> int:
        Address = Address
        if type(Address) == str:
            Address = self.h2d(Address)
        if is64Bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        if self.is64bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        return int.from_bytes(self.Pymem.read_bytes(Address, 4), "little")

    def isValidPointer(self, Address: int, is64Bit: bool = None) -> bool:
        try:
            if type(Address) == str:
                Address = self.h2d(Address)
            self.Pymem.read_bytes(self.DRP(Address, is64Bit), 1)
            return True
        except:
            return False

    def GetModules(self) -> list:
        return list(self.Pymem.list_modules())

    def getAddressFromName(self, Address: str) -> int:
        if type(Address) == int:
            return Address
        AddressBase = 0
        AddressOffset = 0
        for i in self.GetModules():
            if i.name in Address:
                AddressBase = i.lpBaseOfDll
                AddressOffset = self.h2d(Address.replace(i.name + "+", ""))
                AddressNamed = AddressBase + AddressOffset
                return AddressNamed
        print(f'{Fore.RED}[-] Unable to find Address {str(Address)}{Style.RESET_ALL}')
        return Address

    def getNameFromAddress(self, Address: int) -> str:
        memoryInfo = pymem.memory.virtual_query(self.Pymem.process_handle, Address)
        BaseAddress = memoryInfo.BaseAddress
        NameOfDLL = ""
        AddressOffset = 0
        for i in self.GetModules():
            if i.lpBaseOfDll == BaseAddress:
                NameOfDLL = i.name
                AddressOffset = Address - BaseAddress
                break
        if NameOfDLL == "":
            return Address
        NameOfAddress = NameOfDLL + "+" + self.d2h(AddressOffset)
        return NameOfAddress

    def getRawProcesses(self):
        toreturn = []
        for i in pymem.process.list_processes():
            toreturn.append(
                [
                    i.cntThreads,
                    i.cntUsage,
                    i.dwFlags,
                    i.dwSize,
                    i.pcPriClassBase,
                    i.szExeFile,
                    i.th32DefaultHeapID,
                    i.th32ModuleID,
                    i.th32ParentProcessID,
                    i.th32ProcessID,
                ]
            )
        return toreturn

    def SimpleGetProcesses(self):
        toreturn = []
        for i in self.getRawProcesses():
            toreturn.append({"Name": i[5].decode(), "Threads": i[0], "ProcessId": i[9]})
        return toreturn

    def YieldForProgram(self, programName, AutoOpen: bool = False, Limit=15):
        Count = 0
        while True:
            if Count > Limit:
                return False
            ProcessesList = self.SimpleGetProcesses()
            for i in ProcessesList:
                if i["Name"] == programName:
                    #print(f'{Fore.GREEN}[+] Found {programName} with PID: {str(i["ProcessId"])}{Style.RESET_ALL}')
                    if AutoOpen:
                        self.Pymem.open_process_from_id(i["ProcessId"])
                        self.ProgramName = programName
                        self.Handle = self.Pymem.process_handle
                        self.is64bit = pymem.process.is_64_bit(self.Handle)
                        self.ProcessID = self.Pymem.process_id
                        self.PID = self.ProcessID
                        #print(f'{Fore.GREEN}[+] Successfully attached to PID: {str(i["ProcessId"])}{Style.RESET_ALL}')
                    return True
            time.sleep(1)
            Count += 1

    def ReadPointer(
        self, BaseAddress: int, Offsets_L2R: list, is64Bit: bool = None
    ) -> int:
        x = self.DRP(BaseAddress, is64Bit)
        y = Offsets_L2R
        z = x
        if y == None or len(y) == 0:
            return z
        count = 0
        for i in y:
            try:
                print(f'{Fore.WHITE}{Style.DIM}[*] {str(self.d2h(x + i))}{Style.RESET_ALL}')
                print(f'{Fore.WHITE}{Style.DIM}[*] {str(self.d2h(i))}{Style.RESET_ALL}')
                z = self.DRP(z + i, is64Bit)
                count += 1
                print(f'{Fore.WHITE}{Style.DIM}[*] {str(self.d2h(z))}{Style.RESET_ALL}')
            except:
                print(f'{Fore.RED}[-] Failed to read Offset at {str(count)}{Style.RESET_ALL}')
                return z
        return z

    def GetMemoryInfo(self, Address: int, Handle: int = None):
        if Handle:
            return pymem.memory.virtual_query(Handle, Address)
        else:
            return pymem.memory.virtual_query(self.Handle, Address)

    def MemoryInfoToDictionary(self, MemoryInfo):
        return {
            "BaseAddress": MemoryInfo.BaseAddress,
            "AllocationBase": MemoryInfo.AllocationBase,
            "AllocationProtect": MemoryInfo.AllocationProtect,
            "RegionSize": MemoryInfo.RegionSize,
            "State": MemoryInfo.State,
            "Protect": MemoryInfo.Protect,
            "Type": MemoryInfo.Type,
        }

    def SetProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        pymem.ressources.kernel32.VirtualProtectEx(
            self.Pymem.process_handle,
            Address,
            Size,
            ProtectionType,
            ctypes.byref(OldProtect),
        )
        return OldProtect

    def ChangeProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        return self.SetProtection(Address, ProtectionType, Size, OldProtect)

    def GetProtection(self, Address: int):
        return self.GetMemoryInfo(Address).Protect

    def KnowProtection(self, Protection):
        if Protection == 0x10:
            return "PAGE_EXECUTE"
        if Protection == 0x20:
            return "PAGE_EXECUTE_READ"
        if Protection == 0x40:
            return "PAGE_EXECUTE_READWRITE"
        if Protection == 0x80:
            return "PAGE_EXECUTE_WRITECOPY"
        if Protection == 0x01:
            return "PAGE_NOACCESS"
        if Protection == 0x02:
            return "PAGE_READONLY"
        if Protection == 0x04:
            return "PAGE_READWRITE"
        if Protection == 0x08:
            return "PAGE_WRITECOPY"
        if Protection == 0x100:
            return "PAGE_GUARD"
        if Protection == 0x200:
            return "PAGE_NOCACHE"
        if Protection == 0x400:
            return "PAGE_WRITECOMBINE"
        if Protection in ["PAGE_EXECUTE", "execute", "e"]:
            return 0x10
        if Protection in [
            "PAGE_EXECUTE_READ",
            "execute read",
            "read execute",
            "execute_read",
            "read_execute",
            "er",
            "re",
        ]:
            return 0x20
        if Protection in [
            "PAGE_EXECUTE_READWRITE",
            "execute read write",
            "execute write read",
            "write execute read",
            "write read execute",
            "read write execute",
            "read execute write",
            "erw",
            "ewr",
            "wre",
            "wer",
            "rew",
            "rwe",
        ]:
            return 0x40
        if Protection in [
            "PAGE_EXECUTE_WRITECOPY",
            "execute copy write",
            "execute write copy",
            "write execute copy",
            "write copy execute",
            "copy write execute",
            "copy execute write",
            "ecw",
            "ewc",
            "wce",
            "wec",
            "cew",
            "cwe",
        ]:
            return 0x80
        if Protection in ["PAGE_NOACCESS", "noaccess", "na", "n"]:
            return 0x01
        if Protection in ["PAGE_READONLY", "readonly", "ro", "r"]:
            return 0x02
        if Protection in ["PAGE_READWRITE", "read write", "write read", "wr", "rw"]:
            return 0x04
        if Protection in ["PAGE_WRITECOPY", "write copy", "copy write", "wc", "cw"]:
            return 0x08
        if Protection in ["PAGE_GUARD", "pg", "guard", "g"]:
            return 0x100
        if Protection in ["PAGE_NOCACHE", "nc", "nocache"]:
            return 0x200
        if Protection in ["PAGE_WRITECOMBINE", "write combine", "combine write"]:
            return 0x400
        return Protection

    def Suspend(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcess(pid)
        if self.PID:
            kernel32.DebugActiveProcess(self.PID)

    def Resume(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcessStop(pid)
        if self.PID:
            kernel32.DebugActiveProcessStop(self.PID)

Netflix = Netflix()


def getWindowsPlayer():
    while not Netflix.ProcessID:
        #print(f'{Fore.WHITE}{Style.DIM}[*] Finding RobloxPlayerBeta.exe{Style.RESET_ALL}')
        Netflix.YieldForProgram("RobloxPlayerBeta.exe", True, 1)

def getUniversalPlayer():
    while not Netflix.ProcessID:
        #print(f'{Fore.WHITE}{Style.DIM}[*] Finding Windows10Universal.exe{Style.RESET_ALL}')
        Netflix.YieldForProgram("Windows10Universal.exe", True, 1)

print(f'{Fore.GREEN}[+] Finding Roblox Client{Style.RESET_ALL}')
winThread = threading.Thread(target = getWindowsPlayer)
uniThread = threading.Thread(target = getUniversalPlayer)
winThread.start()
uniThread.start()
while not Netflix.ProcessID:
    pass
print(f'{Fore.GREEN}[+] Found {Netflix.ProgramName == "RobloxPlayerBeta.exe" and "Windows" or "Universal"} Client{Style.RESET_ALL}')

def ReadRobloxString(ExpectedAddress: int) -> str:
    StringCount = Netflix.Pymem.read_int(ExpectedAddress + 0x10)
    if StringCount > 15:
        return Netflix.Pymem.read_string(Netflix.DRP(ExpectedAddress), StringCount)
    return Netflix.Pymem.read_string(ExpectedAddress, StringCount)

def GetClassName(Instance: int) -> str:
    ExpectedAddress = Netflix.DRP(Netflix.DRP(Instance + 0x18) + 8)
    return ReadRobloxString(ExpectedAddress)

def SetParent(Instance, Parent):
    Netflix.Pymem.write_longlong(Instance + parentOffset, Parent)
    newChildren = Netflix.Pymem.allocate(0x400)
    Netflix.Pymem.write_longlong(newChildren + 0, newChildren + 0x40)
    ptr = Netflix.Pymem.read_longlong(Parent + childrenOffset)
    childrenStart = Netflix.Pymem.read_longlong(ptr) or 0
    childrenEnd = Netflix.Pymem.read_longlong(ptr + 8) or 0
    b = Netflix.Pymem.read_bytes(childrenStart, childrenEnd - childrenStart)
    Netflix.Pymem.write_bytes(newChildren + 0x40, b, len(b))
    e = newChildren + 0x40 + (childrenEnd - childrenStart)
    Netflix.Pymem.write_longlong(e, Instance)
    Netflix.Pymem.write_longlong(e + 8, Netflix.Pymem.read_longlong(Instance + 0x10))
    e = e + 0x10
    Netflix.Pymem.write_longlong(newChildren + 0x8, e)
    Netflix.Pymem.write_longlong(newChildren + 0x10, e)

## uses everything to inject
def inject():
    global parentOffset
    global nameOffset
    global childrenOffset
    global localPlayerOffset
    players = 0
    valid = False
    results = Netflix.AOBSCANALL('506C6179657273??????????????????07000000000000000F', True)
    if not results:
        close(f'{Fore.RED}[!] AOB scan failed{Style.RESET_ALL}')

    def searchResults(result, searchedResults, forceResult: int = 0):
        global nameOffset
        players = 0
        searchedResults += 1
        first = True
        if forceResult:
            res = forceResult
        else:
            removeLines()
            print(f'{Fore.WHITE}{Style.DIM}[*] Scanning {searchedResults}/{len(results)}{Style.RESET_ALL}')
            bres = Netflix.d2h(result)
            aobs = ""
            for i in range(1, 16 + 1):
                aobs = aobs + bres[i - 1 : i]
            aobs = Netflix.hex2le(aobs)
            res = Netflix.AOBSCANALL(aobs, True)
        if res:
            for i in res:
                try:
                    result = i
                    for j in range(1, 10 + 1):
                        address = result - (8 * j)
                        if not Netflix.isValidPointer(address,):
                            continue
                        ptr = Netflix.Pymem.read_longlong(address)
                        if Netflix.isValidPointer(ptr):
                            address = ptr + 8
                            if not Netflix.isValidPointer(address):
                                continue
                            ptr = Netflix.Pymem.read_longlong(address)
                            if (Netflix.Pymem.read_string(ptr) == "Players"):
                                removeLines()
                                if first:
                                    first = False
                                    players = (result - (8 * j)) - 0x18
                                    nameOffset = result - players
                                    #updateOffset('nameOffset', nameOffset)
                                    #updateOffset('baseResult', res)
                                    print(f'{Fore.GREEN}{Style.DIM}[+] Found possible Players service: {Netflix.d2h(players)}{Style.RESET_ALL}')
                                else:
                                    players = (result - (8 * j)) - 0x18
                                    nameOffset = result - players
                                    #updateOffset('nameOffset', nameOffset)
                                    #updateOffset('baseResult', res)
                                    print(f'{Fore.GREEN}[+] Found Players service: {Netflix.d2h(players)}{Style.RESET_ALL}')
                                    return True, searchedResults, players
                                if searchedResults != len(results):
                                    print(f'{Fore.WHITE}{Style.DIM}[*] Scanning {searchedResults}/{len(results)}{Style.RESET_ALL}')
                except:
                    pass
        return False, searchedResults, players



    try:
        forceResult = offsets['baseResult']
        print(f'{Fore.WHITE}{Style.DIM}[*] Testing cached Players service address list{Style.RESET_ALL}')
        print(f'{Fore.WHITE}{Style.DIM}[*] Attempting to use cached address list{Style.RESET_ALL}')
        Found, ___, players = searchResults([], 0, forceResult)
        if players != 0:
            print(f'{Fore.WHITE}{Style.DIM}[*] Used cached address list{Style.RESET_ALL}')
        else:
            removeLines(2)

    except KeyError:
        pass
    if players == 0:
        try:
            searchable = results[offsets['playersServiceLocation']]
            print(f'{Fore.WHITE}{Style.DIM}[*] Testing cached Players service location{Style.RESET_ALL}')
            print(f'{Fore.WHITE}{Style.DIM}[*] Scanning 1/{len(results)}{Style.RESET_ALL}')
            Found, ___, players = searchResults(searchable, 0)
            if players != 0:
                print(f'{Fore.WHITE}{Style.DIM}[*] Used cached location{Style.RESET_ALL}')
            else:
                removeLines(2)

        except KeyError:
            pass
    searchedResults = 0
    if players == 0:
        print(f'{Fore.WHITE}{Style.DIM}[*] Scanning 1/{len(results)}{Style.RESET_ALL}')
        for result in results:
            Found, searchedResults, playersCached = searchResults(result, searchedResults)
            if playersCached != 0:
                players = playersCached
            if Found:
                #updateOffset('playersServiceLocation', searchedResults - 1)
                break
    if players == 0:
        close(f'{Fore.RED}[-] No Players service{Style.RESET_ALL}')



    print(f'{Fore.GREEN}[+] Name offset: {nameOffset}{Style.RESET_ALL}')



    def getParentOffset(offset):
        global parentOffset
        address = players + offset
        if not Netflix.isValidPointer(address):
            return 0
        ptr = Netflix.Pymem.read_longlong(address)
        if ptr != 0 and ptr % 4 == 0:
            address = ptr + 8
            if not Netflix.isValidPointer(address):
                return 0
            if Netflix.Pymem.read_longlong(address) == ptr:
                parentOffset = offset
                #updateOffset('parentOffset', parentOffset)
                return parentOffset
        return 0
    if parentOffset != 0 and getParentOffset(parentOffset):
        pass
    else:
        for i in range(0x10, 0x120 + 8, 8):
            if getParentOffset(i):
                break
        if parentOffset == 0:
            close(f'{Fore.RED}[-] No parent offset{Style.RESET_ALL}')
    print(f'{Fore.GREEN}[+] Parent offset: {parentOffset}{Style.RESET_ALL}')
    dataModel = Netflix.Pymem.read_longlong(players + parentOffset)



    def getChildrenOffset(offset):
        global childrenOffset
        address = dataModel + offset
        if not Netflix.isValidPointer(address):
            return 0
        ptr = Netflix.Pymem.read_longlong(address)
        if ptr:
            try:
                childrenStart = Netflix.Pymem.read_longlong(ptr)
                childrenEnd = Netflix.Pymem.read_longlong(ptr + 8)
                if childrenStart and childrenEnd:
                    if (
                        childrenEnd > childrenStart
                        and childrenEnd - childrenStart > 1
                        and childrenEnd - childrenStart < 0x1000
                    ):
                        childrenOffset = offset
                        #updateOffset('childrenOffset', childrenOffset)
                        return childrenOffset
            except:
                pass
        return 0

    if childrenOffset != 0 and getChildrenOffset(childrenOffset):
        pass
    else:
        for i in range(0x10, 0x200 + 8, 8):
            getChildrenOffset(i)
        if childrenOffset == 0:
            close(f'{Fore.RED}[-] No children offset{Style.RESET_ALL}')
    
    print(f'{Fore.GREEN}[+] Children offset: {childrenOffset}{Style.RESET_ALL}')

    def GetNameAddress(Instance: int) -> int:
        ExpectedAddress = Netflix.DRP(Instance + nameOffset, True)
        return ExpectedAddress

    def GetName(Instance: int) -> str:
        ExpectedAddress = GetNameAddress(Instance)
        return ReadRobloxString(ExpectedAddress)

    def GetChildren(Instance: int) -> str:
        ChildrenInstance = []
        InstanceAddress = Instance
        if not InstanceAddress:
            return False
        ChildrenStart = Netflix.DRP(InstanceAddress + childrenOffset, True)
        if ChildrenStart == 0:
            return []
        ChildrenEnd = Netflix.DRP(ChildrenStart + 8, True)
        OffsetAddressPerChild = 0x10
        CurrentChildAddress = Netflix.DRP(ChildrenStart, True)
        for i in range(0, 9000):
            if i == 8999:
                print(f'{Fore.RED}[-] Too many children, pointers may be invalid{Style.RESET_ALL}')
            if CurrentChildAddress == ChildrenEnd:
                break
            ChildrenInstance.append(Netflix.Pymem.read_longlong(CurrentChildAddress))
            CurrentChildAddress += OffsetAddressPerChild
        return ChildrenInstance

    def GetParent(Instance: int) -> int:
        return Netflix.DRP(Instance + parentOffset, True)

    def FindFirstChild(Instance: int, ChildName: str, Recursive: bool = False) -> int:
        ChildrenOfInstance = GetChildren(Instance)
        for i in ChildrenOfInstance:
            if GetName(i) == ChildName:
                return i
            if Recursive:
                found = FindFirstChild(i, ChildName, Recursive)
                if found:
                    return found
        return 0

    def FindFirstChildOfClass(Instance: int, ClassName: str, Recursive: bool = False) -> int:
        ChildrenOfInstance = GetChildren(Instance)
        for i in ChildrenOfInstance:
            if GetClassName(i) == ClassName:
                return i
            if Recursive:
                found = FindFirstChildOfClass(i, ClassName, Recursive)
                if found:
                    return found
        return 0

    class toInstance:
        def __init__(self, address: int = 0):
            self.Address = address
            self.Self = address
            self.Name = GetName(address)
            self.ClassName = GetClassName(address)
            self.Parent = GetParent(address)

        def getChildren(self):
            return GetChildren(self.Address)

        def findFirstChild(self, ChildName, Recursive: bool = False):
            return FindFirstChild(self.Address, ChildName, Recursive)

        def findFirstClass(self, ChildClass, Recursive: bool = False):
            return FindFirstChildOfClass(self.Address, ChildClass, Recursive)

        def setParent(self, Parent):
            SetParent(self.Address, Parent)

        def GetChildren(self):
            return GetChildren(self.Address)

        def FindFirstChild(self, ChildName, Recursive: bool = False):
            return FindFirstChild(self.Address, ChildName, Recursive)

        def FindFirstClass(self, ChildClass, Recursive: bool = False):
            return FindFirstChildOfClass(self.Address, ChildClass, Recursive)

        def SetParent(self, Parent):
            SetParent(self.Address, Parent)

    playersService = toInstance(players)
    gameInstance = toInstance(dataModel)

    class DataModel:
        def __init__(self, dataModel):
            self.ReplicatedStorage = toInstance(dataModel.FindFirstChild('ReplicatedStorage'))
            self.replicatedStorage = self.ReplicatedStorage
            self.Workspace = toInstance(dataModel.FindFirstChild('Workspace'))
            self.workspace = self.Workspace
            self.ReplicatedFirst = toInstance(dataModel.FindFirstChild('ReplicatedFirst'))
            self.replicatedFirst = self.ReplicatedFirst
            self.Players = playersService
            self.players = playersService
    
    game = DataModel(gameInstance)

    for i in range(0x10, 0x600 + 4, 4):
        ptr = Netflix.Pymem.read_longlong(playersService.Self + i)
        if not Netflix.isValidPointer(ptr):
            continue
        if Netflix.Pymem.read_longlong(ptr + parentOffset) == playersService.Self:
            localPlayerOffset = i
            break


    localPlayer = toInstance(Netflix.DRP(playersService.Self + localPlayerOffset))
    print(f'{Fore.GREEN}[+] Found LocalPlayer{Style.RESET_ALL}')
    localBackpack = localPlayer.FindFirstClass("Backpack")
    targetScript = None

    def printChildren(Address, Depth: int = 0):
        for scriptAddress in GetChildren(Address):
            if GetClassName(scriptAddress) == 'LocalScript':
                print(f'{Fore.WHITE}{Style.DIM}{"  " * Depth}[+] {GetName(scriptAddress)} ({GetClassName(scriptAddress)}){Style.RESET_ALL}')
            printChildren(scriptAddress, Depth + 1)

    #printChildren(gameInstance.FindFirstChild('Workspace'))
    if localBackpack == 0:
        print(f'{Fore.RED}[-] No backpack found{Style.RESET_ALL}')
    else:
        localBackpack = toInstance(localBackpack)
        print(f'{Fore.GREEN}[+] Found Backpack: {Netflix.d2h(localBackpack.Address)}{Style.RESET_ALL}')
        tools = localBackpack.GetChildren()

        if len(tools) > 0:
            tool = toInstance(tools[0])
            print(f'{Fore.GREEN}[+] Found tool: {tool.Name}{Style.RESET_ALL}')
            targetScript = tool.FindFirstClass("LocalScript", True)
            if targetScript == 0:
                print(f'{Fore.RED}[-] No tool script found{Style.RESET_ALL}')
                printChildren(tool.Address)
            else:
                targetScript = toInstance(targetScript)
                print(f'{Fore.GREEN}[+] Found tool script: {Netflix.d2h(targetScript.Address)}{Style.RESET_ALL}')
        else:
            print(f'{Fore.RED}[-] No tool found{Style.RESET_ALL}')

    if not targetScript:
        playerScripts = toInstance(localPlayer.FindFirstChild('PlayerScripts'))
        print(f'{Fore.GREEN}[+] Found PlayerScripts{Style.RESET_ALL}')
        for scriptAddress in playerScripts.GetChildren():
            print(f'{Fore.WHITE}{Style.DIM}[+] {GetName(scriptAddress)} ({GetClassName(scriptAddress)}){Style.RESET_ALL}')


    injectScript = 0
    results = Netflix.AOBSCANALL("496E6A656374????????????????????06", True)
    if results == []:
        close(f'{Fore.RED}[-] Failed to scan for injection payload{Style.RESET_ALL}')
    for rn in results:
        result = rn
        bres = Netflix.d2h(result)
        aobs = ""
        for i in range(1, 16 + 1):
            aobs = aobs + bres[i - 1 : i]
        aobs = Netflix.hex2le(aobs)
        first = False
        res = Netflix.AOBSCANALL(aobs, True)
        if res:
            valid = False
            for i in res:
                result = i
                if (Netflix.Pymem.read_longlong(result - nameOffset + 8) == result - nameOffset):
                    injectScript = result - nameOffset
                    valid = True
                    break
        if valid:
            break

    if injectScript == 0:
        close(f'{Fore.RED}[-] No injection payload found{Style.RESET_ALL}')
    injectScript = toInstance(injectScript)
    print(f'{Fore.GREEN}[+] Found injection payload: {Netflix.d2h(injectScript.Address)}{Style.RESET_ALL}')

    if targetScript:
        b = Netflix.Pymem.read_bytes(injectScript.Self + 0x100, 0x150)
        Netflix.Pymem.write_bytes(targetScript.Self + 0x100, b, len(b))
    else:
        close(f'{Fore.RED}[-] Injection failed, Please try another game{Style.RESET_ALL}')
    return True

print(f'Join {Fore.LIGHTBLUE_EX}https://roblox.com/games/15167092402{Style.RESET_ALL} before visiting your target game')

input(f'After teleporting press enter to continue...')

print(f'{Fore.WHITE}{Style.DIM}[*] Injecting...{Style.RESET_ALL}')

if inject():
    print(f'{Fore.GREEN}[+] Successfuly Injected{Style.RESET_ALL}!')
    print(f'{Fore.GREEN}[+] Equip your tool until the UI shows{Style.RESET_ALL}')
else:
    print(f'{Fore.RED}[-] Injection Failed{Style.RESET_ALL}!')
    print(f'{Fore.RED}[-] Join {Fore.LIGHTBLUE_EX}discord.gg/byefron{Style.RESET_ALL} for help')
