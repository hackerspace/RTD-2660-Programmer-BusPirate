#!/usr/bin/env python
# -*- coding: utf-8 -*-

import smbus
import time
import os
import sys
import getopt

USAGE = """\
    -r FILE, --save=FILE - reads mem of RTD2662 and dump it into file
    -w FILE, --flash=FILE - erases RTD2662, then flashes file into it
    -e, --erase - erases RTD2662
    Without params will show info about plugged chip
    Options may be combined, ile -r backup.bin -w newfw.bin will first backup the dump, and then flash new one.
"""

E_CC_NOOP = 0
E_CC_WRITE = 1
E_CC_READ = 2
E_CC_WRITE_AFTER_WREN = 3
E_CC_WRITE_AFTER_EWSR = 4
E_CC_ERASE = 5

def sleep1() :
    """Sleep for 1 millisecond"""
    time.sleep(.001)

def FindChip (jedec_id):
    FlashDevices = (
	# name,        Jedec ID,    sizeK, page size, block sizeK
    ( "AT25DF041A", 0x1F4401, 512     , 256, 64)
    , ("AT25DF161" , 0x1F4602, 2 * 1024, 256, 64)
	, ("AT26DF081A", 0x1F4501, 1 * 1024, 256, 64)
	, ("AT26DF0161", 0x1F4600, 2 * 1024, 256, 64)
	, ("AT26DF161A", 0x1F4601, 2 * 1024, 256, 64)
	, ("AT25DF321" , 0x1F4701, 4 * 1024, 256, 64)
	, ("AT25DF512B", 0x1F6501, 64      , 256, 32)
	, ("AT25DF512B", 0x1F6500, 64      , 256, 32)
	, ("AT25DF021" , 0x1F3200, 256     , 256, 64)
	, ("AT26DF641" , 0x1F4800, 8 * 1024, 256, 64)
	, # Manufacturer: ST
    (  "M25P05"    , 0x202010, 64      , 256, 32)
	, ("M25P10"    , 0x202011, 128     , 256, 32)
	, ("M25P20"    , 0x202012, 256     , 256, 64)
	, ("M25P40"    , 0x202013, 512     , 256, 64)
	, ("M25P80"    , 0x202014, 1 * 1024, 256, 64)
	, ("M25P16"    , 0x202015, 2 * 1024, 256, 64)
	, ("M25P32"    , 0x202016, 4 * 1024, 256, 64)
	, ("M25P64"    , 0x202017, 8 * 1024, 256, 64)
	, # Manufacturer: Windbond
    (  "W25X10"    , 0xEF3011, 128     , 256, 64)
	, ("W25X20"    , 0xEF3012, 256     , 256, 64)
	, ("W25X40"    , 0xEF3013, 512     , 256, 64)
	, ("W25X80"    , 0xEF3014, 1 * 1024, 256, 64)
	, # Manufacturer: Macronix
    (  "MX25L512"  , 0xC22010, 64      , 256, 64)
	, ("MX25L3205" , 0xC22016, 4 * 1024, 256, 64)
	, ("MX25L6405" , 0xC22017, 8 * 1024, 256, 64)
	, ("MX25L8005" , 0xC22014, 1024    , 256, 64)
	, #Microchip
    (  "SST25VF512", 0xBF4800, 64      , 256, 32)
	, ("SST25VF032", 0xBF4A00, 4 * 1024, 256, 32)
	, #PUYA
	(  "P25Q40"    , 0x856013, 512     , 256, 64)
	, (           0, 0   , 0       , 0  , 0)
    )
    for Flash in FlashDevices:
        if Flash[1]==jedec_id:
            return Flash
    return None

def GetManufacturedId ( jedec_id ):
    return jedec_id >> 16

def GetManufacturerName ( jedec_id ):
    id = GetManufacturedId ( jedec_id )
    if id==0x20:
        return "ST"
    elif id==0xef:
        return "Winbond"
    elif id==0x1f:
        return "Atmel"
    elif id==0xc2:
        return "Macronix"
    elif id==0xbf:
        return "Microchip"
    elif id==0x85:
        return "PUYA"

    return "Unknown"


def SetupChipCommands ( jedec_id, pr ):
    id = GetManufacturedId ( jedec_id )
    if id==0xef or id==0x85:
        print("Setup chip commands for Winbond...")
        # These are the codes for Winbond
        pr.WriteReg ( 0x62, 0x6 )  #// Flash Write enable op code
        pr.WriteReg ( 0x63, 0x50 ) #// Flash Write register op code
        pr.WriteReg ( 0x6a, 0x3 )  #// Flash Read op code.
        pr.WriteReg ( 0x6b, 0xb )  #// Flash Fast read op code.
        pr.WriteReg ( 0x6d, 0x2 )  #// Flash program op code.
        pr.WriteReg ( 0x6e, 0x5 )  #// Flash read status op code.
    else:
        print("Can not handle manufacturer code %02x\n" % id)
        sys.exit ( -6 )


class CRC():
    """Computes CRC in the memory"""

    def __init__(self):
        self.gCrc=0

    def ProcessCRC (self, data):
        for byte in data:
            self.gCrc ^= byte<<8
            for i in range(8):
                if self.gCrc & 0x8000:
                    self.gCrc ^= 0x1070<<3
                self.gCrc <<= 1

    def GetCRC(self):
        return ( self.gCrc >>8 ) & 0xFF

class BitStream():

    def __init__(self, data):
        self.mask = 0x80
        self.data = data
        self.dataptr = 0
        self.datalen = len(data)

    def HasData(self):
        return (not self.mask == 0) or (not self.datalen == 0)

    def DataSize(self):
        return self.datalen

    def ReadBit(self):
        if not self.mask:
            self.__NextMask()

        bres = ord(self.data[self.dataptr]) & self.mask
        self.mask >>= 1
        return bres

    def __NextMask(self):
        if self.datalen:
            self.mask = 0x80
            self.dataptr += 1
            self.datalen -= 1

class Nibble(BitStream):
    def Decode(self):
        zerocnt = 0
        while zerocnt<6:
            if not self.HasData():
                return 0xf0
            if self.ReadBit():
                break
            zerocnt += 1
        if zerocnt>5:
            if self.DataSize()==1:
                return 0xf0
            return 0xff

        if zerocnt == 0:
            return 0
        elif zerocnt == 1:
            return 0xf if self.ReadBit() else 1
        elif zerocnt == 2:
            return 8 if self.ReadBit() else 2
        elif zerocnt == 3:
            return 7 if self.ReadBit() else 0xc
        elif zerocnt == 4:
            if self.ReadBit():
                return 9 if self.ReadBit() else 4
            elif self.ReadBit():
                return 5 if self.ReadBit() else 0xa
            else:
                return 0xb if self.ReadBit() else 3
        elif zerocnt == 5:
            if self.ReadBit():
                return 0xd if self.ReadBit() else 0xe
            else:
                return 6 if self.ReadBit() else 0xff
        return 0xff

class rtd():
    """speaks over i2c with RTD2660"""

    def __init__(self, bus, addr):
        self.addr = addr
        self.b = smbus.SMBus(bus)

    def WriteReg ( self, reg, data ):
        return self.b.write_byte_data(self.addr, reg, data)

    def ReadByteFromAddr (self, reg):
        return self.b.read_byte_data(self.addr, reg)

    def ReadBytesFromAddr (self, reg, length):
        if length>64:
            length=64
        self.b.write_byte_data(self.addr, reg, length)
        data = []
        for x in range(length):
            data.append(self.b.read_byte(self.addr))
        return data

    def WriteBytesToAddr (self, reg, data):
        self.b.write_i2c_block_data(self.addr, reg, data)

    def ReadReg (self, reg):
        return self.b.read_byte_data(self.addr, reg)

class SPI():
    """SPI interface over i2c"""

    def __init__(self, i2c):
        self.b = i2c

    def SPICommonCommand (self, cmd_type, cmd_code, nreads, nwrites, wvalue):
        nreads = nreads & 3
        nwrites = nwrites & 3
        wvalue =  wvalue & 0xFFFFFF
        reg_value = (cmd_type<<5) | (nwrites<<3) | (nreads<<1)

        self.b.WriteReg(0x60, reg_value)
        self.b.WriteReg(0x61, cmd_code)
        if nwrites==3:
            self.b.WriteReg (0x64, wvalue>>16 )
            self.b.WriteReg (0x65, wvalue >> 8 )
            self.b.WriteReg (0x66, wvalue )
        elif nwrites==2:
            self.b.WriteReg (0x64, wvalue>>8)
            self.b.WriteReg (0x65, wvalue)
        elif nwrites==1:
            self.b.WriteReg (0x64, wvalue)

        self.b.WriteReg (0x60, reg_value | 1)

        while self.b.ReadReg (0x60) & 1:
            sleep1()
            continue

        if nreads==0:
            return 0
        elif nreads==1:
            return self.b.ReadReg (0x67)
        elif nreads==2:
            return (self.b.ReadReg (0x67)<<8) | self.b.ReadReg (0x68)
        elif nreads==3:
            return (self.b.ReadReg(0x67)<<16) | (self.b.ReadReg (0x68)<<8) | self.b.ReadReg (0x69)
        return 0

    def SPIRead (self, address, length):
        self.b.WriteReg(0x60, 0x46 )
        self.b.WriteReg(0x61, 0x3)
        self.b.WriteReg(0x64, address >> 16)
        self.b.WriteReg(0x65, address >> 8)
        self.b.WriteReg(0x66, address)
        self.b.WriteReg(0x60, 0x47) # Execute the command

        while self.b.ReadReg (0x60) & 1:
            sleep1()
            continue

        data = []
        while len(data) < length:
            data += self.b.ReadBytesFromAddr ( 0x70, length - len(data))

        return data

    def SPIComputeCRC (self, start, end):
        self.b.WriteReg(0x64, start >> 16)
        self.b.WriteReg(0x65, start >> 8)
        self.b.WriteReg(0x66, start)

        self.b.WriteReg(0x72, end >> 16)
        self.b.WriteReg(0x73, end >> 8)
        self.b.WriteReg(0x74, end)

        self.b.WriteReg(0x6f, 0x84)

        while not (self.b.ReadReg(0x6f) & 2):
            sleep1()
            continue

        return self.b.ReadReg (0x75)

def SaveFlash (filename, chip_size, spi):
    fdump = open(filename,"wb")
    crc = CRC()
    addr = 0
    chip_crc = spi.SPIComputeCRC(0, chip_size-1)
    while addr < chip_size:
        sys.stdout.write("Reading %d of %d\r" % (addr, chip_size))
        sys.stdout.flush()
        buf = spi.SPIRead (addr, 1024)
        fdump.write(bytes(buf))
        crc.ProcessCRC(buf)
        addr += 1024

    fdump.close()
    data_crc = crc.GetCRC()
    print("")
    print("Received data CRC %x" % data_crc)
    print("Chip CRC %x" % chip_crc)
    return data_crc==chip_crc


def ComputeGffDecodedSize(data):
    nb = Nibble(data)
    cnt = 0
    while nb.HasData():
        b = nb.Decode()
        if b==0xff:
            return 0
        elif b == 0xf0:
            return cnt
        if nb.Decode()>0xf:
            return 0
        cnt+=1
    return cnt


def DecodeGff(data):
    nb = Nibble (data)
    output=[]
    while nb.HasData():
        n1 = nb.Decode()
        if n1==0xf0:
            return True,''.join(chr(i) for i in output)
        elif n1==0xff:
            return False,None
        n2 = nb.Decode()
        if n2>0xf:
            return False,None
        output.append ( (n1<<4)|n2 )
    return True,''.join(chr(i) for i in output)


def ReadFile (filename):
    fsize = os.stat(filename).st_size
    if fsize > 8*1024*1024:
        print("This file looks too big %d" % fsize)
        return None
    with open (filename, "rb") as fl:
        content = fl.read()
    if content[0:12]=="GMI GFF V1.0":
        print("Detected GFF image")
        if fsize<256:
            print("This file looks too small %d" % fsize)
            return None
        reslt, out = DecodeGff(content[256:])
        if reslt:
            return out
        else:
            return None
    return content


def ShouldProgramPage (buff):
    chff = chr(0xff)
    for ch in buff:
        if not ch == chff:
            return True
    return False


def EraseFlash(pr):
    spi = SPI(pr)
    print("Erasing...")
    spi.SPICommonCommand(E_CC_WRITE_AFTER_EWSR, 1, 0, 1, 0)  # Unprotect the Status Register
    spi.SPICommonCommand(E_CC_WRITE_AFTER_WREN, 1, 0, 1, 0)  # Unprotect the flash
    spi.SPICommonCommand(E_CC_ERASE, 0xc7, 0, 0, 0)  # Chip Erase Erase
    print("done")

def ProgramFlash (filename, chip_size, pr):
    prog = ReadFile(filename)
    if not prog:
        return False

    print("Will write %dKb" % (len(prog)/1024))
    spi = SPI(pr)
    addr = 0
    data_len = len(prog)
    data_ptr = 0
    crc = CRC()
    while addr<chip_size and data_len:
        while pr.ReadReg (0x6f) & 0x40:
            sleep1()
            continue

        sys.stdout.write("Writting addr %x\r" % addr)
        sys.stdout.flush()

        lng = 256
        if lng>data_len:
            lng = data_len
        buff = []
        for i in range (lng):
            buff.append (prog[data_ptr+i])

        data_ptr += lng
        data_len -= lng

        if ShouldProgramPage ( buff ):
            # Set program size-1
            pr.WriteReg(0x71, lng-1)

            # Set the programming address
            pr.WriteReg(0x64, addr >> 16)
            pr.WriteReg(0x65, addr >> 8)
            pr.WriteReg(0x66, addr)

            # Write the content to register 0x70
            lngtowrite = lng
            startbit=0
            while lngtowrite>0:
                prl=32
                if prl>lngtowrite:
                    prl=lngtowrite
                pr.WriteBytesToAddr(0x70, buff[startbit:startbit+prl])
                startbit+=prl
                lngtowrite-=prl

            pr.WriteReg(0x6f, 0xa0)

        crc.ProcessCRC(buff)
        addr += lng

    while pr.ReadReg(0x6f) & 0x40:
        sleep1()
        continue

    spi.SPICommonCommand(E_CC_WRITE_AFTER_EWSR, 1, 0, 1, 0x1c)  # Unprotect the Status Register
    spi.SPICommonCommand(E_CC_WRITE_AFTER_WREN, 1, 0, 1, 0x1c)  # Protect the flash
    data_crc = crc.GetCRC()
    chip_crc = spi.SPIComputeCRC ( 0, addr-1 )
    print("")
    print("Received data CRC %x" % data_crc)
    print("Chip CRC %x" % chip_crc)
    return data_crc == chip_crc


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'r:w:e', ['save=','flash=','erase'])
    except getopt.GetoptError:
        print(USAGE)
        sys.exit(2)

    save = False
    write = False
    erase = False
    infile = ""
    ofile = ""
    for o, a in opts:
        if o in ('-r', '--save'):
            save = True
            ofile = a
        elif o in ('-w','--flash'):
            write = True
            erase = True
            infile = a
        elif o in ('-e', '--erase'):
            erase = True

    pr = rtd(1, 0x4a)
    pr.WriteReg(0x6f, 0x80)
    res = pr.ReadReg(0x6f)
    if res & 0x80 == 0:
        print("Can't enable ISP mode")
        sys.exit(-1)

    spir = SPI(pr)
    jedec_id = spir.SPICommonCommand(E_CC_READ, 0x9f, 3, 0, 0)
    print("JEDEC ID: 0x%x" % jedec_id)

    chip = FindChip(jedec_id)
    if not chip:
        print("Inknown chip ID")
        sys.exit(-1)

    chipsize = chip[2] * 1024
    print("Manufacturer %s " % GetManufacturerName(jedec_id))
    print("Chip: %s" % chip[0])
    print("Size: %dKB" % chip[2])

    # Setup flash command codes
    SetupChipCommands (jedec_id,pr)

    b = spir.SPICommonCommand(E_CC_READ, 0x5, 1, 0, 0)

    print("Flash status register: 0x%x" % (b))

    if save:
        print("Save dump to %s" % ofile)
        SaveFlash(ofile, chipsize, spir)

    if erase:
        EraseFlash(pr)

    if write:
        print("Flashing %s" % infile)
        ProgramFlash(infile, chipsize, pr)


if __name__ == '__main__':
    main()