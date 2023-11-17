import angr
import claripy
import random
import string

class CrackmeResolver:

    def generate_serial(self, name: str):
        '''Generate serial for name
        Input:
            name: str - name for crackme register
        Output:
            pair of name, serial
        '''
        name_length = 0xA # from 0x004012B5 (0xA BYTES + '\0')

        if len(name) >= name_length or len(name) == 0:
            print("[-] Fail \n\t name_length must be > 0x0 and <= 0xA")
            return

        black_symbols = [chr(i) for i in range(0x41)]
        for char in black_symbols:
            if char in name:
                print("[-] Fail \n\t name contain blocked symbol:", char)
                return

        project = angr.Project('bin\CRACKME-31158-df08c0.EXE')
        start_addr = 0x00401228 # push offset name
        avoid_addr = [0x00401362, 0x004013AC] # go to no luck
        success_addr  = 0x0040134D # great work
        initial_state = project.factory.blank_state(addr=start_addr)
         
        name_address = 0x0040218E # from DATA segment
        name = claripy.BVV(bytearray(name.encode('cp1251'))) # static ascii name from symbols >= 0x41 (from 0x00401389)
        initial_state.memory.store(name_address, name) # store name

        serial_length = 0xA # from 0x004012D5 (0xA BYTES + '\0')
        serial_address = 0x0040217E # from DATA segment
        serial = claripy.BVS(b'serial', serial_length * 8)
        initial_state.memory.store(serial_address, serial) # store serial
        [initial_state.solver.add(byte >= 0x30, byte <= 0x7a) for byte in serial.chop(8)] # ascii symbol serial

        simulation = project.factory.simgr(initial_state)
        simulation.explore(find=success_addr, avoid=avoid_addr)

        if simulation.found:
            solution_state = simulation.found[0]
            solution_name = solution_state.solver.eval(name, cast_to=bytes)
            solution_serial = solution_state.solver.eval(serial, cast_to=bytes)
            print("[+] Success: \n\tname is '{}' \n\tserial is: '{}'".format(solution_name.decode('cp1251'), solution_serial.decode('cp1251')))
        else: print("[-] Fail \n\t pair not found")

    def generate_pair(self):
        '''Generate pair name and serial
        Output:
            generated pair of name, serial
        '''
        project = angr.Project('bin\CRACKME-31158-df08c0.EXE')
        start_addr = 0x00401228 # push offset name
        avoid_addr = [0x00401362, 0x004013AC] # go to no luck
        success_addr  = 0x0040134D # great work
        initial_state = project.factory.blank_state(addr=start_addr)

        name_length = 0xA # from 0x004012B5 (0xA BYTES + '\0')
        name_address = 0x0040218E # from DATA segment
        name = claripy.BVV(bytearray(''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(name_length)).encode('cp1251'))) # static ascii name from symbols >= 0x41 (from 0x00401389)
        initial_state.memory.store(name_address, name) # store name

        serial_length = 0xA # from 0x004012D5 (0xA BYTES + '\0')
        serial_address = 0x0040217E # from DATA segment
        serial = claripy.BVS(b'serial', serial_length * 8)
        initial_state.memory.store(serial_address, serial) # store serial
        [initial_state.solver.add(byte >= 0x30, byte <= 0x7a) for byte in serial.chop(8)] # ascii symbol serial

        simulation = project.factory.simgr(initial_state)
        simulation.explore(find=success_addr, avoid=avoid_addr)

        if simulation.found:
            solution_state = simulation.found[0]
            solution_name = solution_state.solver.eval(name, cast_to=bytes)
            solution_serial = solution_state.solver.eval(serial, cast_to=bytes)
            print("[+] Success: \n\tname is '{}' \n\tserial is: '{}'".format(solution_name.decode('cp1251'), solution_serial.decode('cp1251')))
        else: print("[-] Fail")

if __name__ == "__main__":
    resolver = CrackmeResolver()
    resolver.generate_serial("Яблоко")
    resolver.generate_serial("Apple")
    resolver.generate_pair()
   