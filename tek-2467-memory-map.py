#create a memory map for Tektronix 2467
#@author Siggi
#@category Tektronix Oscilloscopes
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.data import ArrayDataType

program = createProgram("2467", ghidra.program.model.lang.LanguageID("MC6800:BE:16:default"))

byte = ghidra.program.model.data.ByteDataType()
ptr = ghidra.program.model.data.Pointer16DataType()
ushort = ghidra.program.model.data.UnsignedShortDataType()

datatype_mgr = program.getDataTypeManager()

def createIODataType(datatype_mgr):
    fine = ghidra.program.model.data.StructureDataType("FD", 0)
    fields = [
        "DMUX2_ON", "DMUX0_OFF", "DMUX0_ON", "PORT3_IN",
        "DMUX1_OFF", "DMUX1_ON", "LED_CLK", "DISP_SEQ_CLK",
        "ATN_CLK", "CH2_PA_CLK", "CH1_PA_CLK", "B_SWP_CLK",
        "A_SWP_CLK", "B_TRIG_CLK", "A_TRIG_CLK", "TRIG_STAT_STRB"]

    for field in fields:
        fine.add(byte, 1, field, "")

    fine_array_4 = ArrayDataType(fine, 4, fine.getLength())
    fine_array_4.setName("f")

    byte_array_64 = ArrayDataType(byte, 64, 1)
    byte_array_64.setName("ba")

    byte_array_63 = ArrayDataType(byte, 63, 1)
    byte_array_64.setName("ba")

    coarse = ghidra.program.model.data.StructureDataType("CD", 0)
    coarse.add(byte_array_64, byte_array_64.getLength(), "DMUX2_OFF", "")
    coarse.add(byte_array_63, byte_array_63.getLength(), "DAC_MSB_CLK", "")
    coarse.add(ushort, 2, "DAC_FULL_CLK", "Writes both DAC bytes in a single 16 bit write.")
    coarse.add(byte_array_63, byte_array_63.getLength(), "DAC_LSB_CLK", "")
    coarse.add(byte_array_64, byte_array_64.getLength(), "PORT_1_CLK", "")
    coarse.add(byte_array_64, byte_array_64.getLength(), "ROS_1_CLK", "")
    coarse.add(byte_array_64, byte_array_64.getLength(), "ROS_2_CLK", "")
    coarse.add(byte_array_64, byte_array_64.getLength(), "PORT2_CLK", "")
    coarse.add(fine_array_4, fine_array_4.getLength(), "", "")

    io = ghidra.program.model.data.StructureDataType("IO", 0)
    io.add(coarse, coarse.getLength(), "0", "")
    io.add(coarse, coarse.getLength(), "1", "")
    io.add(coarse, coarse.getLength(), "2", "")
    io.add(coarse, coarse.getLength(), "3", "")

    return datatype_mgr.addDataType(io, None)

memory = program.memory

# The high RAM mapping is modeled as non-overlay, even though that's not accurate.
# This mapping appears for the latter three ROM overlays, whereas the first ROM
# overlay consumes this address space. Making this a non-overlay mapping helps
# analysis, as data references from the ROM overlays will hit on the RAM.
u2640 = memory.createUninitializedBlock("U2640", toAddr(0x8000), 0x2000, False)
u2640.setWrite(True)

# The base RAM is a mapping of the hi RAM mapping.
lo_ram = memory.createByteMappedBlock("BASE RAM", toAddr(0x0000), u2640.getStart(), 0x0800, False)
lo_ram.setWrite(True)

# Create the IO block.
io_block = memory.createUninitializedBlock("IO", toAddr(0x800), 0x800, False)
io_block.setWrite(True)
io_block.setVolatile(True)
# Give it the right type.
io_data_type = createData(io_block.getStart(), createIODataType(datatype_mgr))

def createAndDisassembleVector(addr, name, suffix):
    createLabel(addr, "VEC_" + name + "_" + suffix, True)
    vector = createData(addr, ptr)

    function = createFunction(vector.getValue(), name + "_" + suffix)
    disassemble(function.getEntryPoint())


def createRomBlock(memory, name, file_bytes, address, offset, length):
    block = memory.createInitializedBlock(name, toAddr(address), file_bytes, offset, length, True)
    block.setExecute(True)

    # Create the vector addresses from the block start address to get
    # addresses in the right address space.
    addr = block.getStart()

    # Start with the RESET vectors, as the SWI vectors also point to the
    # RESET vectors, but we want the functions named RESET_*.
    createAndDisassembleVector(addr.getNewAddress(0xFFFE, True), "RESET", name)
    createAndDisassembleVector(addr.getNewAddress(0xFFFC, True), "NMI", name)
    createAndDisassembleVector(addr.getNewAddress(0xFFFA, True), "SWI", name)
    createAndDisassembleVector(addr.getNewAddress(0xFFF8, True), "IRQ", name)

    return block


input_stream = java.io.FileInputStream("C:/Users/siggi/Documents/2467/ROMS/A5U2160-160-3302-09.bin")
a5u1260 = memory.createFileBytes("A5U2160-160-3302-09.bin", 0, 0x10000, input_stream, None)

u1260b0 = createRomBlock(memory, "U1260B0", a5u1260, 0x8000, 0, 0x8000)
u1260b1 = createRomBlock(memory, "U1260B1", a5u1260, 0xA000, 0xA000, 0x6000)

input_stream = java.io.FileInputStream("C:/Users/siggi/Documents/2467/ROMS/A5U2260-160-3303-09.bin")
a5u2260 = memory.createFileBytes("A5U2260-160-3303-09.bin", 0, 0x10000, input_stream, None)

u2260b0 = createRomBlock(memory, "U2260B0", a5u2260, 0xA000, 0x2000, 0x6000)
u2260b1 = createRomBlock(memory, "U2260B1", a5u2260, 0xA000, 0xA000, 0x6000)
