import os

def createFile(name, size):

    data = "dd" * (int(size / 2) - 1)

    arr = bytearray(data, 'utf-8')

    with open(name, 'wb') as f:
        f.write(arr)

    file_size = os.stat(name).st_size
    print("File created of ", file_size / size, " MB size")

    # `enter code here`Creating 1MB of file with dummy data

createFile("smallFile.txt",1024 )
createFile("largeFile_1MB.txt",1024*1024)
createFile("largeFile.txt",10*1024*1024 )