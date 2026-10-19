#!/usr/bin/env python3
"""
experimento_sal.py - Demuestra para que sirve la sal.

carla y gabriela fueron registradas con la MISMA clave ("costarica") a
proposito. Este script saca sus 4 hashes de la base y los compara:

    * MD5 y SHA-256 (SIN sal)  -> hash IDENTICO para los dos usuarios.
      Eso es justo lo que permite las tablas precalculadas.
    * bcrypt y Argon2id (CON sal) -> hash DISTINTO, aunque la clave es la misma,
      porque cada usuario recibe una sal aleatoria diferente.

Importa listar_usuarios de login.py (no modifica login.py).
"""

from login import listar_usuarios

# Esquemas en el mismo orden que devuelve listar_usuarios: columnas 1..4.
ESQUEMAS = ("md5", "sha256", "bcrypt", "argon2")


def buscar_usuario(filas, nombre):
    """Devuelve la fila (usuario, md5, sha256, bcrypt, argon2) de un usuario."""
    for fila in filas:
        if fila[0] == nombre:
            return fila
    return None


def main():
    filas = listar_usuarios()
    carla = buscar_usuario(filas, "carla")
    gabriela = buscar_usuario(filas, "gabriela")

    if carla is None or gabriela is None:
        print("Faltan carla o gabriela. Corre antes: python login.py -> opcion 4.")
        return

    print("carla y gabriela tienen la MISMA clave de prueba: 'costarica'.\n")

    # Recorremos los 4 esquemas y comparamos el hash de cada una.
    for indice, esquema in enumerate(ESQUEMAS, start=1):
        hash_carla = carla[indice]
        hash_gabriela = gabriela[indice]
        iguales = hash_carla == hash_gabriela

        print(f"--- {esquema.upper()} ---")
        print(f"  carla    : {hash_carla}")
        print(f"  gabriela : {hash_gabriela}")
        if iguales:
            print("  => IGUALES  (no usa sal: dos claves iguales dan el mismo hash)\n")
        else:
            print("  => DISTINTOS (usa sal aleatoria por usuario)\n")

    print("--- CONCLUSION ---")
    print("Sin sal (MD5, SHA-256), la misma clave delata que dos usuarios la comparten")
    print("y permite tablas precalculadas. Con sal (bcrypt, Argon2id), los hashes")
    print("son distintos aunque la clave sea identica.")


if __name__ == "__main__":
    main()
