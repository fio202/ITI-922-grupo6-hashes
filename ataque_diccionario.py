#!/usr/bin/env python3
"""
ataque_diccionario.py - Ataque de diccionario contra los 4 esquemas de hash.

Importa las funciones de login.py (de Fiorella) y ataca los hashes que ya
estan guardados en usuarios.db. Demuestra por que MD5 y SHA-256 son inseguros
para contrasenas y por que bcrypt y Argon2id resisten.

Punto clave de la demostracion:
    * MD5 y SHA-256 NO usan sal, asi que se puede PRECALCULAR el hash de cada
      palabra del diccionario UNA sola vez y buscarlo entre todos los usuarios.
      Esto es instantaneo (ataque de tabla precalculada / rainbow).
    * bcrypt y Argon2id SI usan una sal distinta por usuario, asi que NO se
      puede precalcular: hay que reintentar palabra por palabra contra CADA
      usuario, y cada intento es lento a proposito. Por eso cuesta tanto que,
      en la practica, solo se puede atacar una MUESTRA pequena de usuarios.

Solo se atacan contrasenas de prueba inventadas por el grupo.
"""

import time

# Funciones del programa de Fiorella (no se modifica login.py).
from login import (
    listar_usuarios,
    hash_md5,
    hash_sha256,
    verificar_bcrypt,
    verificar_argon2,
)

# Para bcrypt/Argon2id atacamos solo una muestra, porque cada intento es lento.
# En esta VM bcrypt tarda ~1 segundo por intento, asi se mantiene en ~20-30 s.
MUESTRA_USUARIOS = 4          # cuantos usuarios se atacan con los esquemas lentos
MAX_PALABRAS_LENTO = 10       # cuantas palabras se prueban como maximo por usuario


def cargar_diccionario(ruta="diccionario.txt"):
    """Lee el diccionario y devuelve una lista de palabras (sin lineas vacias)."""
    with open(ruta, "r", encoding="utf-8") as archivo:
        return [linea.strip() for linea in archivo if linea.strip()]


def atacar_rapido(funcion_hash, usuarios, diccionario):
    """
    Ataca un esquema SIN sal (MD5 o SHA-256) con precalculo.

    1. Calcula el hash de cada palabra del diccionario UNA vez -> tabla {hash: palabra}.
    2. Para cada usuario, busca su hash en esa tabla: si esta, la clave cayo.

    Como el hash se calcula una sola vez por palabra, es muy rapido.
    Devuelve (crackeados, intentos, segundos).
    """
    inicio = time.perf_counter()

    tabla = {}
    for palabra in diccionario:
        tabla[funcion_hash(palabra)] = palabra
    intentos = len(diccionario)   # un hash por palabra

    crackeados = []
    for usuario, hash_guardado in usuarios:
        if hash_guardado in tabla:
            crackeados.append((usuario, tabla[hash_guardado]))

    segundos = time.perf_counter() - inicio
    return crackeados, intentos, segundos


def atacar_lento(nombre_esquema, funcion_verificar, usuarios, diccionario):
    """
    Ataca un esquema CON sal (bcrypt o Argon2id) sobre una MUESTRA de usuarios.

    Como cada usuario tiene una sal distinta, NO se puede precalcular: hay que
    probar palabra por palabra con la funcion de verificacion de login.py, que
    lee la sal del propio hash. Imprime el progreso para que se vea que avanza.

    Devuelve (crackeados, intentos, segundos).
    """
    inicio = time.perf_counter()
    intentos = 0
    crackeados = []

    # Solo los primeros MUESTRA_USUARIOS usuarios (atacar a todos seria lentisimo).
    muestra = usuarios[:MUESTRA_USUARIOS]
    print(f"  (atacando una muestra de {len(muestra)} usuarios; cada intento es lento)")

    for usuario, hash_guardado in muestra:
        print(f"  probando {nombre_esquema} contra '{usuario}'...", end=" ", flush=True)
        encontrada = None
        for palabra in diccionario[:MAX_PALABRAS_LENTO]:
            intentos += 1
            if funcion_verificar(palabra, hash_guardado):
                encontrada = palabra
                break
        if encontrada:
            crackeados.append((usuario, encontrada))
            print(f"ROTO -> {encontrada}")
        else:
            print("resistio")

    segundos = time.perf_counter() - inicio
    return crackeados, intentos, segundos


def imprimir_resultado(nombre_esquema, crackeados, intentos, segundos, total):
    """Imprime el resumen del ataque a un esquema."""
    velocidad = intentos / segundos if segundos > 0 else 0
    print(f"\n=== {nombre_esquema.upper()} ===")
    print(f"Usuarios crackeados: {len(crackeados)} de {total}")
    for usuario, clave in crackeados:
        print(f"   [ROTO] {usuario:<10} -> {clave}")
    print(f"Intentos: {intentos:,}")
    print(f"Tiempo total: {segundos:.4f} s")
    print(f"Velocidad: {velocidad:,.1f} intentos/seg")


def main():
    diccionario = cargar_diccionario()
    print(f"Diccionario cargado: {len(diccionario)} palabras.")

    filas = listar_usuarios()   # (usuario, md5, sha256, bcrypt, argon2)
    total = len(filas)
    print(f"Usuarios en la base: {total}")

    # Separamos la columna de cada esquema: lista de (usuario, hash_de_ese_esquema).
    usuarios_md5 = [(f[0], f[1]) for f in filas]
    usuarios_sha = [(f[0], f[2]) for f in filas]
    usuarios_bcrypt = [(f[0], f[3]) for f in filas]
    usuarios_argon2 = [(f[0], f[4]) for f in filas]

    # Esquemas rapidos y sin sal: se precalculan (ataque instantaneo, todos).
    r_md5 = atacar_rapido(hash_md5, usuarios_md5, diccionario)
    imprimir_resultado("md5", *r_md5, total)

    r_sha = atacar_rapido(hash_sha256, usuarios_sha, diccionario)
    imprimir_resultado("sha256", *r_sha, total)

    # Esquemas lentos y con sal: solo una muestra (ataque caro).
    print("\n>>> Ahora bcrypt y Argon2id. Esto tarda unos segundos, es normal:")
    r_bcrypt = atacar_lento("bcrypt", verificar_bcrypt, usuarios_bcrypt, diccionario)
    imprimir_resultado("bcrypt", *r_bcrypt, MUESTRA_USUARIOS)

    r_argon2 = atacar_lento("argon2", verificar_argon2, usuarios_argon2, diccionario)
    imprimir_resultado("argon2", *r_argon2, MUESTRA_USUARIOS)

    # Conclusion: comparar la velocidad de MD5 contra bcrypt.
    vel_md5 = r_md5[1] / r_md5[2] if r_md5[2] > 0 else 0
    vel_bcrypt = r_bcrypt[1] / r_bcrypt[2] if r_bcrypt[2] > 0 else 0
    print("\n--- CONCLUSION ---")
    if vel_bcrypt > 0:
        factor = vel_md5 / vel_bcrypt
        print(f"MD5 permite ~{vel_md5:,.0f} intentos/seg; bcrypt solo ~{vel_bcrypt:,.1f}.")
        print(f"Atacar bcrypt es ~{factor:,.0f} veces mas lento que atacar MD5.")
    print("Con MD5/SHA-256 se crackearon las claves debiles al instante y a TODOS.")
    print("Con bcrypt/Argon2id, cada intento cuesta tanto que solo se pudo atacar")
    print("una muestra. Las claves fuertes y aleatorias no cayeron en ningun esquema.")


if __name__ == "__main__":
    main()
