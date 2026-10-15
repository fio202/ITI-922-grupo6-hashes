#!/usr/bin/env python3
"""
login.py - Sistema de registro e inicio de sesión en consola (ITI-922, Grupo 6).

Guarda la contraseña de cada usuario con 4 esquemas distintos para poder
compararlos:

    * MD5      -> rápido y SIN sal (inseguro, a propósito para la demostración)
    * SHA-256  -> rápido y SIN sal (inseguro, a propósito para la demostración)
    * bcrypt   -> lento, con sal aleatoria incluida en el hash (rounds=12)
    * Argon2id -> lento y "memory-hard", con sal incluida (parámetros OWASP)

Las funciones se pueden importar desde otros scripts, por ejemplo:

    from login import hash_md5, verificar_bcrypt, registrar_usuario

Solo se deben usar contraseñas de prueba inventadas.
"""

import hashlib
import hmac
import secrets
import sqlite3
import string
import time
from getpass import getpass
from pathlib import Path

import bcrypt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

# La base de datos y la carpeta de exportación quedan junto a este archivo,
# así funciona igual sin importar desde qué carpeta se ejecute o importe.
CARPETA_BASE = Path(__file__).resolve().parent
RUTA_BD = CARPETA_BASE / "usuarios.db"
CARPETA_EXPORTADOS = CARPETA_BASE / "exportados"

# Costo de bcrypt: 2^12 = 4096 rondas del algoritmo de expansión de clave.
BCRYPT_ROUNDS = 12

# bcrypt solo procesa los primeros 72 BYTES de la clave (no caracteres:
# una "ñ" o una tilde ocupan 2 bytes en UTF-8).
BCRYPT_MAX_BYTES = 72

# Parámetros de Argon2id según la OWASP Password Storage Cheat Sheet:
# "minimum configuration of 19 MiB of memory, an iteration count of 2,
#  and 1 degree of parallelism" (m=19456 KiB, t=2, p=1).
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
ARGON2_MEMORIA_KIB = 19456   # 19 MiB expresados en KiB (19 * 1024)
ARGON2_ITERACIONES = 2       # time_cost: pasadas sobre la memoria
ARGON2_PARALELISMO = 1       # hilos (lanes)

# Se ponen TODOS los parámetros explícitos, porque los valores por defecto
# de argon2-cffi 25.1.0 son otros (t=3, m=65536, p=4).
HASHER_ARGON2 = PasswordHasher(
    time_cost=ARGON2_ITERACIONES,
    memory_cost=ARGON2_MEMORIA_KIB,
    parallelism=ARGON2_PARALELISMO,
    hash_len=32,      # largo del hash resultante en bytes
    salt_len=16,      # largo de la sal aleatoria en bytes
    type=Type.ID,     # Argon2id (híbrido, el recomendado)
)

# Nombres de los esquemas, en el orden en que se muestran.
ESQUEMAS = ("md5", "sha256", "bcrypt", "argon2")


class ClaveDemasiadoLargaError(ValueError):
    """Se lanza cuando la clave supera los 72 bytes que acepta bcrypt."""


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------

def conectar(ruta_bd=RUTA_BD):
    """
    Abre la base de datos SQLite y crea la tabla 'usuarios' si no existe.

    Devuelve un objeto sqlite3.Connection listo para usar.
    """
    conexion = sqlite3.connect(ruta_bd)
    # UNIQUE en 'usuario' impide registrar dos veces el mismo nombre.
    conexion.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL UNIQUE,
            md5     TEXT NOT NULL,
            sha256  TEXT NOT NULL,
            bcrypt  TEXT NOT NULL,
            argon2  TEXT NOT NULL
        )
        """
    )
    conexion.commit()
    return conexion


# ---------------------------------------------------------------------------
# Funciones de hash (una por esquema)
# ---------------------------------------------------------------------------

def hash_md5(clave):
    """
    Devuelve el MD5 de la clave en hexadecimal (32 caracteres).

    SIN sal a propósito: la misma clave siempre produce el mismo hash,
    lo que permite tablas precalculadas y ataques de diccionario rápidos.
    """
    return hashlib.md5(clave.encode("utf-8")).hexdigest()


def hash_sha256(clave):
    """
    Devuelve el SHA-256 de la clave en hexadecimal (64 caracteres).

    SIN sal a propósito. SHA-256 es un buen hash criptográfico, pero es
    demasiado RÁPIDO para guardar contraseñas.
    """
    return hashlib.sha256(clave.encode("utf-8")).hexdigest()


def validar_largo_bcrypt(clave):
    """
    Lanza ClaveDemasiadoLargaError si la clave ocupa más de 72 bytes en UTF-8.

    bcrypt 5.0.0 ya NO recorta la clave en silencio (las versiones 4.x sí lo
    hacían): ahora lanza ValueError. Aquí se valida antes para dar un mensaje
    claro en español.
    """
    largo = len(clave.encode("utf-8"))
    if largo > BCRYPT_MAX_BYTES:
        raise ClaveDemasiadoLargaError(
            f"La clave ocupa {largo} bytes y bcrypt solo acepta hasta "
            f"{BCRYPT_MAX_BYTES} bytes. Usa una clave más corta "
            "(ojo: letras con tilde o ñ ocupan 2 bytes)."
        )


def hash_bcrypt(clave):
    """
    Devuelve el hash bcrypt de la clave como texto (formato $2b$12$...).

    bcrypt genera una sal aleatoria de 16 bytes y la guarda DENTRO del hash
    (los 22 caracteres que siguen a '$2b$12$'), por eso no hace falta una
    columna aparte para la sal.
    """
    validar_largo_bcrypt(clave)
    sal = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)          # sal nueva cada vez
    return bcrypt.hashpw(clave.encode("utf-8"), sal).decode("ascii")


def hash_argon2(clave):
    """
    Devuelve el hash Argon2id de la clave (formato $argon2id$v=19$m=...).

    El texto resultante incluye el tipo, la versión, los parámetros
    (m, t, p), la sal en base64 y el hash en base64.
    """
    return HASHER_ARGON2.hash(clave)


# ---------------------------------------------------------------------------
# Funciones de verificación (devuelven True o False)
# ---------------------------------------------------------------------------

def verificar_md5(clave, hash_guardado):
    """Devuelve True si el MD5 de la clave coincide con el hash guardado."""
    # compare_digest compara en tiempo constante para no filtrar información
    # por el tiempo que tarda la comparación (ataque de temporización).
    return hmac.compare_digest(hash_md5(clave), hash_guardado)


def verificar_sha256(clave, hash_guardado):
    """Devuelve True si el SHA-256 de la clave coincide con el hash guardado."""
    return hmac.compare_digest(hash_sha256(clave), hash_guardado)


def verificar_bcrypt(clave, hash_guardado):
    """
    Devuelve True si la clave corresponde al hash bcrypt guardado.

    checkpw lee la sal y el costo desde el propio hash, recalcula y compara.
    Una clave de más de 72 bytes nunca pudo registrarse, así que devuelve False.
    """
    try:
        validar_largo_bcrypt(clave)
    except ClaveDemasiadoLargaError:
        return False
    return bcrypt.checkpw(clave.encode("utf-8"), hash_guardado.encode("ascii"))


def verificar_argon2(clave, hash_guardado):
    """
    Devuelve True si la clave corresponde al hash Argon2id guardado.

    PasswordHasher.verify devuelve True si coincide y LANZA una excepción
    si no coincide, por eso se capturan aquí.
    """
    try:
        return HASHER_ARGON2.verify(hash_guardado, clave)
    except VerifyMismatchError:
        # La clave es incorrecta.
        return False
    except (InvalidHashError, VerificationError):
        # El hash guardado está dañado o no es un hash Argon2 válido.
        return False


# Tablas que relacionan cada esquema con su función (útil para recorrerlos).
FUNCIONES_HASH = {
    "md5": hash_md5,
    "sha256": hash_sha256,
    "bcrypt": hash_bcrypt,
    "argon2": hash_argon2,
}
FUNCIONES_VERIFICAR = {
    "md5": verificar_md5,
    "sha256": verificar_sha256,
    "bcrypt": verificar_bcrypt,
    "argon2": verificar_argon2,
}


# ---------------------------------------------------------------------------
# Operaciones del sistema
# ---------------------------------------------------------------------------

def registrar_usuario(usuario, clave, ruta_bd=RUTA_BD):
    """
    Registra un usuario guardando su clave con los 4 esquemas.

    Devuelve True si se registró y False si el usuario ya existía.
    Lanza ValueError si el usuario o la clave están vacíos, y
    ClaveDemasiadoLargaError si la clave supera los 72 bytes de bcrypt.
    """
    usuario = usuario.strip()
    if not usuario or not clave:
        raise ValueError("El usuario y la clave no pueden estar vacíos.")

    # Se validan los 72 bytes ANTES de calcular nada, para no dejar
    # registros a medias.
    validar_largo_bcrypt(clave)

    # Se calcula el hash de la misma clave con cada uno de los 4 esquemas.
    hashes = {esquema: funcion(clave) for esquema, funcion in FUNCIONES_HASH.items()}

    conexion = conectar(ruta_bd)
    try:
        # Los "?" evitan inyección SQL: sqlite3 inserta los valores de forma segura.
        conexion.execute(
            "INSERT INTO usuarios (usuario, md5, sha256, bcrypt, argon2) "
            "VALUES (?, ?, ?, ?, ?)",
            (usuario, hashes["md5"], hashes["sha256"], hashes["bcrypt"], hashes["argon2"]),
        )
        conexion.commit()
        return True
    except sqlite3.IntegrityError:
        # Viola la restricción UNIQUE: el usuario ya existe.
        return False
    finally:
        conexion.close()


def iniciar_sesion(usuario, clave, ruta_bd=RUTA_BD, mostrar=True):
    """
    Verifica la clave del usuario con CADA uno de los 4 esquemas.

    Mide cuánto tarda cada verificación con time.perf_counter().
    Devuelve un diccionario {esquema: (coincide, segundos)}, o None si el
    usuario no existe. Si mostrar=True imprime una tabla con los resultados.
    """
    conexion = conectar(ruta_bd)
    fila = conexion.execute(
        "SELECT md5, sha256, bcrypt, argon2 FROM usuarios WHERE usuario = ?",
        (usuario.strip(),),
    ).fetchone()
    conexion.close()

    if fila is None:
        if mostrar:
            print("Usuario o clave incorrectos.")
        return None

    resultados = {}
    for esquema, hash_guardado in zip(ESQUEMAS, fila):
        inicio = time.perf_counter()                    # reloj de alta precisión
        coincide = FUNCIONES_VERIFICAR[esquema](clave, hash_guardado)
        segundos = time.perf_counter() - inicio
        resultados[esquema] = (coincide, segundos)

    if mostrar:
        print(f"\n{'Esquema':<10}{'Resultado':<14}{'Tiempo':>12}")
        print("-" * 36)
        for esquema, (coincide, segundos) in resultados.items():
            texto = "CORRECTA" if coincide else "incorrecta"
            print(f"{esquema:<10}{texto:<14}{segundos * 1000:>9.3f} ms")
        if all(coincide for coincide, _ in resultados.values()):
            print(f"\nBienvenida/o, {usuario.strip()}. Inicio de sesión exitoso.")
        else:
            print("\nUsuario o clave incorrectos.")
    return resultados


def listar_usuarios(ruta_bd=RUTA_BD):
    """
    Devuelve una lista de tuplas (usuario, md5, sha256, bcrypt, argon2),
    ordenada por id.
    """
    conexion = conectar(ruta_bd)
    filas = conexion.execute(
        "SELECT usuario, md5, sha256, bcrypt, argon2 FROM usuarios ORDER BY id"
    ).fetchall()
    conexion.close()
    return filas


# ---------------------------------------------------------------------------
# Usuarios de prueba y exportación
# ---------------------------------------------------------------------------

def generar_clave_aleatoria(largo=16):
    """
    Genera una clave aleatoria con el módulo secrets (criptográficamente
    seguro, a diferencia de random).
    """
    alfabeto = string.ascii_letters + string.digits + "!@#$%&*-_+="
    return "".join(secrets.choice(alfabeto) for _ in range(largo))


def usuarios_de_prueba():
    """
    Devuelve la lista de (usuario, clave) de prueba, todas INVENTADAS.

    carla y gabriela tienen la MISMA clave a propósito, para el
    experimento de sal: igual MD5/SHA-256, pero distinto bcrypt/Argon2id.
    """
    return [
        ("ana", "123456"),                     # la más común del mundo
        ("bruno", "password"),                 # palabra de diccionario en inglés
        ("carla", "costarica"),                # palabra local en minúsculas
        ("diego", "Saprissa2026"),             # nombre + año
        ("elena", "cartago2024"),              # palabra con números
        ("fabian", "qwerty"),                  # patrón de teclado
        ("gabriela", "costarica"),             # MISMA clave que carla
        ("hector", "Pura_Vida!7"),             # mezcla con símbolo
        ("ivan", generar_clave_aleatoria()),   # aleatoria de 16 caracteres
    ]


def cargar_usuarios_prueba(ruta_bd=RUTA_BD):
    """
    Registra los usuarios de prueba. Los que ya existen se omiten sin error.

    Devuelve una lista de (usuario, clave, creado) donde creado es True/False.
    """
    resultado = []
    for usuario, clave in usuarios_de_prueba():
        creado = registrar_usuario(usuario, clave, ruta_bd)
        resultado.append((usuario, clave, creado))
    return resultado


def exportar_hashes(ruta_bd=RUTA_BD, carpeta=CARPETA_EXPORTADOS):
    """
    Escribe un archivo por esquema en la carpeta 'exportados/' con el
    formato usuario:hash (una línea por usuario), que es el que lee
    John the Ripper.

    Devuelve la lista de rutas de los archivos creados.
    """
    carpeta = Path(carpeta)
    carpeta.mkdir(exist_ok=True)
    filas = listar_usuarios(ruta_bd)
    rutas = []
    for indice, esquema in enumerate(ESQUEMAS, start=1):   # columna 1..4 de la fila
        ruta = carpeta / f"usuarios_{esquema}.txt"
        with open(ruta, "w", encoding="utf-8") as archivo:
            for fila in filas:
                archivo.write(f"{fila[0]}:{fila[indice]}\n")
        rutas.append(ruta)
    return rutas


# ---------------------------------------------------------------------------
# Menú de consola
# ---------------------------------------------------------------------------

def menu_registrar():
    """Pide usuario y clave (dos veces) y registra al usuario."""
    usuario = input("Usuario: ").strip()
    clave = getpass("Clave: ")                 # getpass no muestra lo que se escribe
    if clave != getpass("Repite la clave: "):
        print("Las claves no coinciden.")
        return
    try:
        if registrar_usuario(usuario, clave):
            print(f"Usuario '{usuario}' registrado con los 4 esquemas.")
        else:
            print(f"El usuario '{usuario}' ya existe. Elige otro nombre.")
    except ValueError as error:                # incluye ClaveDemasiadoLargaError
        print(f"Error: {error}")


def menu_iniciar_sesion():
    """Pide usuario y clave y muestra la verificación con los 4 esquemas."""
    usuario = input("Usuario: ")
    clave = getpass("Clave: ")
    iniciar_sesion(usuario, clave)


def menu_listar():
    """Muestra cada usuario con sus 4 hashes."""
    filas = listar_usuarios()
    if not filas:
        print("No hay usuarios registrados.")
        return
    for usuario, *hashes in filas:
        print(f"\n[{usuario}]")
        for esquema, valor in zip(ESQUEMAS, hashes):
            print(f"  {esquema:<7}: {valor}")


def menu_cargar_prueba():
    """Carga los usuarios de prueba y muestra cuáles se crearon."""
    for usuario, clave, creado in cargar_usuarios_prueba():
        if creado:
            print(f"  + {usuario:<10} creado   (clave de prueba: {clave})")
        else:
            print(f"  = {usuario:<10} ya existía, se omite")


def menu_exportar():
    """Exporta los hashes a la carpeta exportados/."""
    for ruta in exportar_hashes():
        print(f"  Creado: {ruta.relative_to(CARPETA_BASE)}")


def main():
    """Muestra el menú principal en un ciclo hasta que se elija 0."""
    opciones = {
        "1": menu_registrar,
        "2": menu_iniciar_sesion,
        "3": menu_listar,
        "4": menu_cargar_prueba,
        "5": menu_exportar,
    }
    while True:
        print(
            "\n=== Sistema de login (MD5 / SHA-256 / bcrypt / Argon2id) ===\n"
            "1. Registrar\n"
            "2. Iniciar sesión\n"
            "3. Ver usuarios y sus 4 hashes\n"
            "4. Cargar usuarios de prueba\n"
            "5. Exportar hashes\n"
            "0. Salir"
        )
        opcion = input("Opción: ").strip()
        if opcion == "0":
            print("Hasta luego.")
            break
        accion = opciones.get(opcion)
        if accion:
            accion()
        else:
            print("Opción no válida.")


# Solo se ejecuta el menú si se corre "python login.py"; si otro script hace
# "import login", se pueden usar las funciones sin que aparezca el menú.
if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nSaliendo.")
