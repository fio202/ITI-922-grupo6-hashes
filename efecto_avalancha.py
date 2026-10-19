#!/usr/bin/env python3
"""
efecto_avalancha.py - Demuestra el "efecto avalancha" de una funcion hash.

Propiedad: cambiar UN solo caracter de la entrada cambia aproximadamente la
MITAD de los bits del hash. Es lo que hace que un hash no "se parezca" a otro
aunque las entradas sean casi iguales.

Comparamos dos claves que difieren en un caracter y contamos cuantos bits
cambian en el hash (MD5 y SHA-256).

Importa hash_md5 y hash_sha256 de login.py (no modifica login.py).
"""

from login import hash_md5, hash_sha256


def hex_a_bits(texto_hex):
    """
    Convierte un hash en hexadecimal a una cadena de bits ('0' y '1').

    Cada digito hex son 4 bits. Ej: 'a' = 1010. zfill(4) rellena con ceros
    a la izquierda para que cada digito ocupe siempre 4 bits.
    """
    bits = ""
    for digito in texto_hex:
        valor = int(digito, 16)          # pasa el digito hex a numero 0..15
        bits += bin(valor)[2:].zfill(4)  # bin(10) -> '0b1010'; [2:] quita '0b'
    return bits


def contar_bits_distintos(hash_a, hash_b):
    """
    Cuenta en cuantos bits difieren dos hashes del mismo largo.

    Devuelve (bits_distintos, bits_totales).
    """
    bits_a = hex_a_bits(hash_a)
    bits_b = hex_a_bits(hash_b)
    distintos = sum(1 for x, y in zip(bits_a, bits_b) if x != y)
    return distintos, len(bits_a)


def analizar(nombre, funcion_hash, clave1, clave2):
    """Hashea dos claves, compara sus bits e imprime el resultado."""
    h1 = funcion_hash(clave1)
    h2 = funcion_hash(clave2)
    distintos, totales = contar_bits_distintos(h1, h2)
    porcentaje = distintos / totales * 100

    print(f"--- {nombre.upper()} ---")
    print(f"  clave 1 ('{clave1}') -> {h1}")
    print(f"  clave 2 ('{clave2}') -> {h2}")
    print(f"  Bits distintos: {distintos} de {totales}  ({porcentaje:.1f} %)\n")


def main():
    # Dos claves que difieren en UN solo caracter (la ultima).
    clave1 = "costarica1"
    clave2 = "costarica2"
    print(f"Comparando '{clave1}' vs '{clave2}' (difieren en 1 caracter).\n")

    analizar("md5", hash_md5, clave1, clave2)
    analizar("sha256", hash_sha256, clave1, clave2)

    print("--- CONCLUSION ---")
    print("Cambiar un solo caracter cambia cerca del 50 % de los bits del hash.")
    print("Por eso no se puede adivinar la entrada 'acercandose' al hash objetivo.")


if __name__ == "__main__":
    main()
