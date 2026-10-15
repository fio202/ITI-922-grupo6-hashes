# ITI-922 — Grupo 6: Hashes y contraseñas

Proyecto del curso ITI-922. Compara cómo se guardan contraseñas con cuatro
esquemas distintos: **MD5**, **SHA-256**, **bcrypt** y **Argon2id**.

> Este repositorio contiene **solo contraseñas de prueba inventadas**. Nada de
> datos reales.

---

## Sección de Fiorella — `login.py`

### Descripción

`login.py` es un sistema de **registro e inicio de sesión en consola** (sin
Flask) que usa **SQLite** como base de datos. Cuando se registra un usuario, su
contraseña se guarda **hasheada con los cuatro esquemas a la vez**, para poder
compararlos:

| Esquema  | Sal | Velocidad | ¿Sirve para contraseñas? |
|----------|-----|-----------|--------------------------|
| MD5      | No  | Muy rápido | No (roto, sin sal) |
| SHA-256  | No  | Muy rápido | No (demasiado rápido, sin sal) |
| bcrypt   | Sí (automática) | Lento (rounds=12) | Sí |
| Argon2id | Sí (automática) | Lento + mucha memoria | Sí (el más recomendado) |

MD5 y SHA-256 se usan **sin sal a propósito**, para demostrar por qué son
inseguros. Las funciones están separadas y se pueden **importar** desde otros
scripts (ataques de diccionario, experimento de sal, efecto avalancha, HMAC):

```python
from login import hash_md5, verificar_bcrypt, registrar_usuario, listar_usuarios
```

### Requisitos

- Ubuntu 24.04 (o similar)
- Python 3.12
- Paquetes del sistema: `python3-venv`, `python3-pip`, `git`, `sqlite3`
- Librerías de Python (en `requirements.txt`): `bcrypt==5.0.0`,
  `argon2-cffi==25.1.0`

### Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/fio202/ITI-922-grupo6-hashes.git
cd ITI-922-grupo6-hashes

# 2. Crear y activar el entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar las librerías con las versiones exactas
pip install -r requirements.txt
```

### Cómo ejecutar

```bash
source venv/bin/activate   # si no está activado
python login.py
```

Aparece un menú con estas opciones:

| Opción | Qué hace |
|--------|----------|
| **1. Registrar** | Pide usuario y clave (con `getpass`, no se ve) y la guarda con los 4 hashes. |
| **2. Iniciar sesión** | Verifica la clave con los 4 esquemas y muestra **cuánto tardó cada uno**. |
| **3. Ver usuarios** | Lista cada usuario con sus 4 hashes. |
| **4. Cargar usuarios de prueba** | Inserta 9 usuarios de ejemplo (no falla si ya existen). |
| **5. Exportar hashes** | Crea `exportados/usuarios_*.txt` en formato `usuario:hash` (para John the Ripper). |
| **0. Salir** | Termina. |

### Parámetros de seguridad

- **bcrypt:** `rounds=12`. Las claves de más de **72 bytes** se rechazan con un
  mensaje claro (bcrypt 5.0.0 lanza error en vez de recortar en silencio).
- **Argon2id:** `m=19456 KiB (19 MiB)`, `t=2`, `p=1`, según la
  [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

### Archivos que NO se suben al repo

`venv/`, `__pycache__/`, `usuarios.db` y `exportados/` están en `.gitignore`:
se generan en cada máquina al ejecutar el programa.

Más detalle en [`docs/guia_fiorella.md`](docs/guia_fiorella.md).
