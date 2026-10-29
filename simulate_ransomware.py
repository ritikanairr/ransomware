import os, time, base64

BASE = r"C:\Users\ritik\Downloads\ransomware-detector-main\ransomware-detector-main\TestFiles\sim"
os.makedirs(BASE, exist_ok=True)

def p(name): return os.path.join(BASE, name)

def create_samples():
    for i in range(12):
        with open(p(f"doc{i}.txt"), "w") as f:
            f.write(("Quarterly notes, meeting minutes, plain readable text.\n" * 40))
    print("Samples created. Now start the detector, then run simulate().")

def simulate():
    # 1. Normal edit: should be "Legitimate modification"
    with open(p("doc0.txt"), "a") as f:
        f.write("One extra line added by a normal user.\n")
    time.sleep(1)

    # 2. Raw ciphertext-like: random bytes overwrite the file
    with open(p("doc1.txt"), "wb") as f:
        f.write(os.urandom(4096))
    time.sleep(1)

    # 3. Base64 ciphertext-like: should trigger the Base64 transition alert
    with open(p("doc2.txt"), "wb") as f:
        f.write(base64.b64encode(os.urandom(2048)))
    time.sleep(1)

    # 4. Rename with a suspicious extension
    os.rename(p("doc3.txt"), p("doc3.txt.locked"))
    time.sleep(1)

    # 5. Mass modification: overwrite many files quickly (rate alert)
    for i in range(4, 12):
        with open(p(f"doc{i}.txt"), "wb") as f:
            f.write(os.urandom(2048))

    # 6. Mass deletion
    time.sleep(1)
    for i in range(4, 12):
        os.remove(p(f"doc{i}.txt"))

if __name__ == "__main__":
    import sys
    create_samples() if sys.argv[1:] == ["setup"] else simulate()