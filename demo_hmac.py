#!/usr/bin/env python3
"""
demo_hmac.py - Demuestra para que sirve HMAC (integridad + autenticidad).

Un hash normal (MD5, SHA-256) solo comprueba INTEGRIDAD: si el mensaje cambia,
el hash cambia. Pero cualquiera puede recalcular el hash del mensaje alterado,
asi que no prueba QUIEN lo genero.

HMAC usa ademas una LLAVE secreta compartida. Solo quien tiene la llave puede
generar o verificar el codigo. Si el mensaje se altera, la verificacion falla;
y sin la llave, un atacante no puede fabricar un HMAC valido.

Usa el modulo hmac de la libreria estandar (no hace falta instalar nada).
"""

import hmac
import hashlib


def generar_hmac(llave, mensaje):
    """
    Genera el HMAC-SHA256 de un mensaje con una llave.

    Las dos entradas se codifican a bytes (utf-8) porque hmac trabaja con bytes.
    Devuelve el resultado en hexadecimal.
    """
    return hmac.new(
        llave.encode("utf-8"),
        mensaje.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verificar_hmac(llave, mensaje, hmac_recibido):
    """
    Recalcula el HMAC del mensaje y lo compara con el recibido.

    Usa compare_digest (tiempo constante) para no filtrar informacion por el
    tiempo de comparacion. Devuelve True si coinciden.
    """
    hmac_calculado = generar_hmac(llave, mensaje)
    return hmac.compare_digest(hmac_calculado, hmac_recibido)


def main():
    llave = "clave_secreta_del_grupo6"   # en la vida real iria en un lugar seguro
    mensaje = "Transferir 1000 colones a la cuenta 12345"

    # El emisor genera el HMAC y envia (mensaje + hmac).
    etiqueta = generar_hmac(llave, mensaje)
    print("Mensaje original :", mensaje)
    print("HMAC generado    :", etiqueta, "\n")

    # Caso 1: el receptor recibe el mensaje intacto -> debe verificar OK.
    print("--- Caso 1: mensaje intacto ---")
    ok = verificar_hmac(llave, mensaje, etiqueta)
    print("Verificacion:", "VALIDA (nadie lo altero)" if ok else "FALLA", "\n")

    # Caso 2: un atacante altera el mensaje pero NO tiene la llave.
    mensaje_alterado = "Transferir 9999 colones a la cuenta 67890"
    print("--- Caso 2: mensaje alterado por un atacante ---")
    print("Mensaje alterado :", mensaje_alterado)
    ok = verificar_hmac(llave, mensaje_alterado, etiqueta)
    print("Verificacion:", "VALIDA" if ok else "FALLA (se detecto la alteracion)", "\n")

    print("--- CONCLUSION ---")
    print("Con el mensaje intacto el HMAC verifica; si se altera el mensaje, falla.")
    print("Sin la llave secreta, el atacante no puede fabricar un HMAC valido:")
    print("HMAC da integridad Y autenticidad, no solo integridad como un hash suelto.")


if __name__ == "__main__":
    main()
