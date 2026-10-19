#!/usr/bin/env python3
"""
graficos.py - Genera los 2 graficos PNG para el informe y las diapositivas.

1. grafico_tiempos.png   -> tiempo que tarda UN hash con cada esquema (ms).
2. grafico_intentos.png  -> cuantos intentos por segundo permite cada esquema.

Mide los tiempos reales llamando a las funciones de login.py varias veces y
sacando el promedio. Usa matplotlib con backend 'Agg', que guarda la imagen a
un archivo SIN necesidad de pantalla (importante en Ubuntu Server).

Requiere: pip install matplotlib
"""

import time

import matplotlib
matplotlib.use("Agg")   # backend sin ventana: guarda a archivo, no abre nada
import matplotlib.pyplot as plt

from login import hash_md5, hash_sha256, hash_bcrypt, hash_argon2

ESQUEMAS = ["MD5", "SHA-256", "bcrypt", "Argon2id"]
FUNCIONES = [hash_md5, hash_sha256, hash_bcrypt, hash_argon2]


def medir_tiempo_promedio(funcion, repeticiones):
    """
    Mide el tiempo promedio (en milisegundos) de una funcion de hash.

    Para MD5/SHA (muy rapidos) conviene repetir muchas veces; para bcrypt/argon2
    (lentos) con pocas repeticiones basta.
    """
    clave = "costarica"
    inicio = time.perf_counter()
    for _ in range(repeticiones):
        funcion(clave)
    total = time.perf_counter() - inicio
    return (total / repeticiones) * 1000  # ms por hash


def main():
    tiempos_ms = []
    for nombre, funcion in zip(ESQUEMAS, FUNCIONES):
        # Menos repeticiones para los lentos, muchas para los rapidos.
        repeticiones = 50 if nombre in ("bcrypt", "Argon2id") else 20000
        ms = medir_tiempo_promedio(funcion, repeticiones)
        tiempos_ms.append(ms)
        print(f"{nombre:<10}: {ms:.5f} ms por hash")

    # intentos/seg = cuantos hashes caben en un segundo = 1000 ms / (ms por hash).
    intentos_seg = [1000.0 / ms for ms in tiempos_ms]

    # --- Grafico 1: tiempo por hash (escala log por la diferencia enorme) ---
    plt.figure(figsize=(8, 5))
    colores = ["#c0392b", "#e67e22", "#27ae60", "#2980b9"]
    plt.bar(ESQUEMAS, tiempos_ms, color=colores)
    plt.yscale("log")  # sin log, MD5 y SHA se verian pegados a cero
    plt.ylabel("Tiempo por hash (ms, escala logaritmica)")
    plt.title("Costo de calcular un hash segun el esquema")
    for i, ms in enumerate(tiempos_ms):
        plt.text(i, ms, f"{ms:.3f} ms", ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.savefig("resultados/grafico_tiempos.png", dpi=150)
    plt.close()
    print("Guardado: resultados/grafico_tiempos.png")

    # --- Grafico 2: intentos por segundo (tambien escala log) ---
    plt.figure(figsize=(8, 5))
    plt.bar(ESQUEMAS, intentos_seg, color=colores)
    plt.yscale("log")
    plt.ylabel("Intentos por segundo (escala logaritmica)")
    plt.title("Cuantas claves por segundo puede probar un atacante")
    for i, v in enumerate(intentos_seg):
        plt.text(i, v, f"{v:,.0f}", ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.savefig("resultados/grafico_intentos.png", dpi=150)
    plt.close()
    print("Guardado: resultados/grafico_intentos.png")


if __name__ == "__main__":
    main()
