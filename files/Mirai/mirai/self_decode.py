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

buf = "\x70\x67\x72\x6D\x70\x76\x02\x07\x51\x18\x07\x51\x22"
unlock(buf,len(buf))
