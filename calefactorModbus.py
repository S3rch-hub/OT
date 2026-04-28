import threading
from pwn import remote, context
import struct
import time
context.log_level = 'error'  # Usado para no mostrar el mensajes de conexion abierta y cerrada cuando se hace el escaneo de coils

HOST = "localhost"
PORT = 502
UID = 1
COILS = [16, 36, 52, 78] # Direeciones de los coil sacadas tras haber lanzado escaneo con el modulo de modbusclient para leer coils
UMBRAL = 5
UMBRAL_SECURE = 97

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

"""def refill(conn,uid):
    currentLevel = read_hregister(conn,uid, 27)
    if currentLevel <= 0 + UMBRAL:
        write_coil(conn, uid, 1350, True) # Se abre grifo para rellenar
    
        while True:
            currentLevel = read_hregister(conn,uid, 27)
            if (currentLevel + UMBRAL) >= 100:
                write_coil(conn, uid, 1350, False) # Se cierra el grifo
                break
"""

def refill(conn, uid):
    currentLevel = read_hregister(conn, uid, 27)
    if currentLevel <= (UMBRAL+5):  # Se anade un margen de seguridad
        write_coil(conn, uid, 1350, True)  # Abre grifo
        while True:
            currentLevel = read_hregister(conn, uid, 26)
            if currentLevel >= (100 - UMBRAL):  
                write_coil(conn, uid, 1350, False)  # Cierra grifo
                break
            time.sleep(0.3)
    
def secureRefill(conn, uid, UMBRAL_SECURE):
    while True:
        currentLevel= read_hregister(conn,uid, 26)
        if currentLevel >= UMBRAL_SECURE:
            write_coil(conn, uid, 1350, False) 
            write_coil(conn,uid,1346, True)
            time.sleep(12)
            write_coil(conn,uid,1346, False) # Se desactiva ya el freno de emergencia
        time.sleep(0.3)


if __name__ == "__main__":
    
    with remote(HOST, PORT) as conn:
     
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
        
        """ Funcionalidad para saber los coils en el escenario 2
        for addr in range(0, 2000):
            try:
                conn = remote(HOST, PORT, timeout=2)
                state = read_coil(conn, 25, addr)
                print(f"Coil {addr}: {state}")
                conn.close()
            except Exception as e:
                conn.close()
        """
        """ Funcionalidad para ir escribiendo en cada coil encontrado y cambiando el estado para ver qué ocurre
        for addr in range(1337, 1360):
            try:
                conn = remote(HOST, PORT, timeout=2)
                write_coil(conn, 25, addr, True)
                print(f"Coil {addr}")
                conn.close()
            except Exception as e:
                conn.close()
        """

    # Escenario 2: dos conexiones separadas para evitar colisiones
    conn_refill = remote(HOST, PORT)
    conn_secure = remote(HOST, PORT)

    thread = threading.Thread(target=secureRefill, args=(conn_secure, 25, UMBRAL_SECURE))
    thread.daemon = True
    thread.start()

    while True:
        refill(conn_refill, 25)
        time.sleep(0.5)



