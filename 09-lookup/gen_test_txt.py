from random import shuffle
with open("./forwarding-table.txt", "rb") as f:
    lines = f.readlines()
    shuffle(lines)
    with open("./test.txt", "wb") as t:
        for i in range(10):
            t.write(lines[i])

