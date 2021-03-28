

def numtoChar(src):
    str = ""
    for i in src:
        str +=chr(i)
    print(str)
    
def getFold(str):
    ii = [2,4,6,8,10,12]
    fold = 0xAF
    for i in ii:
        fold += ~ord(str[i % len(str)])
    print(fold,fold%9)
src = [0x2e, 0x2f,0x64,0x76,0x72,0x48,0x65,0x6c,0x70,0x65,0x72,0x00]
numtoChar(src)
getFold("./dvrHelper")
