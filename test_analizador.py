# tests/test_analizador.py

import sys
import os
sys.path.insert(0, os.path.abspath('.'))  # cambia el nombre para las pruebas a sabbat_analizalogs.py, por ejemplo.

from sabbat_analizalogs import AnalizadorLogs

def test_extraer_ips_validas():
    analizador = AnalizadorLogs("dummy.log")  # no se abre el archivo en esta prueba

    # Casos de prueba
    linea1 = 'Acceso desde 192.168.1.1 y 8.8.8.8'
    ips1 = analizador.extraer_ips_validas(linea1)
    assert ips1 == ['8.8.8.8']  # 192.168.1.1 es privada → se filtra

    linea2 = 'Conexión IPv6: 2001:4860:4860::8888 y ::1' # Usamos la DNS de Google
    ips2 = analizador.extraer_ips_validas(linea2)
    assert ips2 == ['2001:4860:4860::8888'] 

    linea3 = 'IP inválida: 999.999.999.999 y texto'
    ips3 = analizador.extraer_ips_validas(linea3)
    assert ips3 == []

    linea4 = 'Log normal con 1.1.1.1 y "User-Agent: curl"'
    ips4 = analizador.extraer_ips_validas(linea4)
    assert ips4 == ['1.1.1.1']
