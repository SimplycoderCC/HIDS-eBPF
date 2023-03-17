import ctypes
import os
binary = open('./date','rb').read()
fd =  ctypes.CDLL(None).syscall(319,"",1)
final_fd = open('/proc/self/fd/'+str(fd),'wb')
final_fd.write(binary)
final_fd.close()
os.execl('/proc/self/fd/'+str(fd),"")