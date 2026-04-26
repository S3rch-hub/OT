from pwn import remote
import struct

HOST = "localhost"
PORT = 502
UID = 1
COILS = [16, 36, 52, 78] # Direeciones de los coil sacadas tras haber lanzado escaneo con el modulo de modbusclient para leer coils

def scanning_devices(conn): # Función utilziada para el Escenario 2.
    for uid in range(1,200):
        try:
            conn.timeout = 1 
            state = read_coil(conn, uid, 16)
            print(f"Device found with UID: {uid} and state is: {state}")
        except Exception as e:
            print(f"UID {uid} is not responding: {e}")


# Paquete Modbus: Transaction ID (2 bytes), Protocol ID (2 bytes), Length (2 bytes), Unit ID (1 byte), Function Code (1 byte), Data (En este caso 1 byte)
def read_coil(conn, uid, start_address):
    transaction_id = 1
    protocol_id = 0 
    function_code = 0x01 

    header = struct.pack(">HHH", transaction_id, protocol_id, 6)
    pdu = bytes([uid, function_code]) + struct.pack(">HH", start_address, 1)
    modbuspacket = header + pdu 
    conn.send(modbuspacket)
    response = conn.recv(1024)

    function_code_response = response[7] # response[7]  va a tener el valor de la respuesta del dispositivo, si es igual al fcode, todo ha salido bien
    exception_code = response[8] # Valor de retorno que ha generado la excepción
    if function_code_response >= 0x80: # Si hay un erro, se le suma a response[7] 0x80
        raise Exception(f"An error was detected!{exception_code:02X}")
    coil_state = response[9] # Valor del coil
    
    return bool(coil_state & 0x01)

# Paquete Modbus: Transaction ID (2 bytes), Protocol ID (2 bytes), Length (2 bytes), Unit ID (1 byte), Function Code (1 byte), Data (True = 0xFF00, False = 0x0000)
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
    

def read_hregister(conn, uid, start_address):
    transaction_id = 1
    protocol_id = 0
    function_code = 0x03

    header = struct.pack(">HHH", transaction_id, protocol_id, 6)
    pdu = bytes([uid, function_code]) + struct.pack(">HH", start_address, 1)
    modbuspacket = header + pdu
    conn.send(modbuspacket)
    response = conn.recv(1024)

    function_code_response = response[7]
    exception_code = response[8]
    if function_code_response >= 0x80:
        raise Exception(f"An error was detected!{exception_code:02X}")
    
    registerValue = struct.unpack(">H", response[9:11])[0] # Cojo los 2 bytes que devuelve y los convierto a entero
    return registerValue

def set_all(conn, uid, temp):
    for i in range(len(COILS)):
        write_coil(conn, uid, COILS[i], temp)

if __name__ == "__main__":
    
    with remote(HOST, PORT) as conn:

        scanning_devices(conn)


        # Primera funcionalidad donde se muestra el estado de todos los coils
        for c in COILS:
            try:
                estado = read_coil(conn, UID, c)
                print(f"  {c}: {estado}")
            except:
                pass
        # Para la segunda funcionalidad , se van a poner todos en False. 
        for c in COILS:
            try:
                write_coil(conn, UID, c, False)
                newestado = read_coil(conn, UID, c)
                print(f"  {c}: {newestado}")
            except:
                pass
        for c in COILS:
            try:
                registerValue = read_hregister(conn, UID, c)
                print(f"  {c}: {registerValue}")
            except:
                pass
        # Para la tercera funcionalidad, se van a poner todos en True.
        set_all(conn, UID, True)
        for c in COILS:
            try:
                newestado = read_coil(conn, UID, c)
                print(f"  {c}: {newestado}")
            except:
                pass
        
        

