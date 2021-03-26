def unlock(buf, len):
    table_key = 0xdeadbeef
    k1 = table_key & 0xff
    k2 = (table_key >> 8) & 0xff
    k3 = (table_key >>16) & 0xff
    k4 = (table_key >>24) & 0xff
    new = list(range(len))
    for i in range(0,len):
        print("now index = %d with buf[%d]=%c\n" % (i,i,buf[i]) )
        new[i] = ord(buf[i]) ^ k1 ^ k2 ^ k3 ^ k4
        print("after, buf_new[%d]=%c\n" % (i,new[i]))
    print(new)
    new = [chr(i) for i in new]
    print("".join(new))
    return buf

buf = "\x50\x47\x52\x4D\x50\x56\x0C\x41\x4A\x43\x4C\x45\x47\x4F\x47\x0C\x41\x4D\x4F\x22"
unlock(buf,len(buf))
