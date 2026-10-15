# Guía paso a paso — Fiorella (desde Ubuntu limpio)

Esta guía explica, línea por línea, cómo montar y ejecutar mi parte del
proyecto (`login.py`) empezando desde un Ubuntu recién instalado.

> Marca **[CAPTURA]** = aquí conviene tomar una captura de pantalla para el
> informe o la defensa.

---

## 1. Instalar los programas del sistema

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git sqlite3
```

- `sudo apt update` → refresca la lista de paquetes disponibles.
- `apt install -y ...` → instala sin preguntar (`-y` = responder "sí"):
  - `python3-venv` → permite crear entornos virtuales de Python.
  - `python3-pip` → instalador de librerías de Python.
  - `git` → control de versiones (para los commits).
  - `sqlite3` → base de datos y su cliente de consola.

**[CAPTURA]** del final de la instalación (líneas "Configurando ...").

Verificar que quedaron instalados:

```bash
python3 --version   # debe decir Python 3.12.x
git --version
sqlite3 --version
```

---

## 2. Clonar el repositorio y configurar git

```bash
git clone https://github.com/fio202/ITI-922-grupo6-hashes.git
cd ITI-922-grupo6-hashes
git config --global user.name "Fiorella Zamora Campos"
git config --global user.email "fizamocam@gmail.com"
```

- `git clone URL` → descarga una copia del repositorio.
- `cd ...` → entra a la carpeta del proyecto.
- `git config --global user.name/email` → pone mi nombre y correo para que
  **los commits salgan a mi nombre**.

**[CAPTURA]** de `git config --global --list` mostrando mi nombre y correo.

---

## 3. Crear el entorno virtual e instalar las librerías

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

- `python3 -m venv venv` → crea una carpeta `venv/` con un Python "aparte", para
  no ensuciar el Python del sistema.
- `source venv/bin/activate` → **activa** el entorno. A partir de aquí el prompt
  muestra `(venv)` al inicio.
- `pip install -r requirements.txt` → instala las librerías con las versiones
  exactas (`bcrypt==5.0.0`, `argon2-cffi==25.1.0`).

**[CAPTURA]** del prompt con `(venv)` y de `pip list` mostrando bcrypt y argon2.

> Si NO uso `requirements.txt`, puedo instalarlas a mano:
> `pip install bcrypt argon2-cffi`

---

## 4. Ejecutar el programa

```bash
python login.py
```

Aparece el menú. Recorrido recomendado para la demostración:

1. **Opción 4** (Cargar usuarios de prueba) → crea 9 usuarios de ejemplo.
   **[CAPTURA]**
2. **Opción 3** (Ver usuarios) → muestra cada usuario con sus 4 hashes.
   **[CAPTURA]** (aquí se ve que carla y gabriela tienen el MISMO md5).
3. **Opción 2** (Iniciar sesión) → probar con `carla` / `costarica` (correcta) y
   luego con una clave mala. Fijarse en la columna **Tiempo**: MD5 y SHA-256
   tardan microsegundos, bcrypt y Argon2id tardan milisegundos. **[CAPTURA]**
4. **Opción 1** (Registrar) → crear un usuario nuevo inventado. **[CAPTURA]**
5. **Opción 5** (Exportar hashes) → genera la carpeta `exportados/`. **[CAPTURA]**
6. **Opción 0** → salir.

---

## 5. Ver la base de datos directamente con SQLite

```bash
sqlite3 usuarios.db "SELECT usuario, md5, bcrypt FROM usuarios;"
```

- Abre la base `usuarios.db` y ejecuta la consulta: muestra el nombre, el MD5 y
  el bcrypt de cada usuario.

**Demostración del efecto de la sal** (carla y gabriela usan la misma clave):

```bash
sqlite3 usuarios.db "SELECT usuario, md5, bcrypt FROM usuarios WHERE usuario IN ('carla','gabriela');"
```

- Se ve que el **md5 es idéntico** (MD5 no usa sal) pero el **bcrypt es distinto**
  (bcrypt le pone una sal aleatoria distinta a cada uno).

**[CAPTURA]** de esta comparación: es la prueba clave del experimento de sal.

---

## 6. (Opcional) Verificar el formato con John the Ripper

```bash
john --format=raw-md5 --show exportados/usuarios_md5.txt
```

- Comprueba que John **carga** los hashes exportados (formato `usuario:hash`).
- La versión básica de Ubuntu (`apt install john`) solo trae `bcrypt`. Para
  `raw-md5`, `raw-sha256` y `argon2` se necesita la versión **jumbo**:
  `sudo snap install john-the-ripper` y usar el binario `john-the-ripper`.

---

## Problemas comunes y solución

### "error: externally-managed-environment" al usar pip
**Causa:** se intentó instalar con pip en el Python del sistema, sin activar el
entorno virtual.
**Solución:** crear/activar el venv primero:
```bash
python3 -m venv venv
source venv/bin/activate
```
Luego `pip install ...` funciona dentro del `(venv)`.

### El programa no encuentra bcrypt o argon2 ("ModuleNotFoundError")
**Causa:** el entorno virtual no está activado (no aparece `(venv)` en el prompt).
**Solución:** `source venv/bin/activate` y volver a ejecutar.

### "El usuario 'x' ya existe"
**Causa:** ese nombre ya está en la base (la columna `usuario` es UNIQUE).
**Solución:** usar otro nombre, o borrar la base para empezar de cero:
`rm usuarios.db` (ojo: borra todos los usuarios).

### "La clave ocupa N bytes y bcrypt solo acepta hasta 72 bytes"
**Causa:** bcrypt solo procesa los primeros **72 bytes** de la clave. Las letras
con tilde o la "ñ" ocupan **2 bytes** cada una en UTF-8.
**Solución:** usar una clave más corta. El programa lo valida y avisa antes de
guardar, así no quedan registros a medias.

### `source venv/bin/activate` no hace nada / "No such file or directory"
**Causa:** el venv no se creó, o no estoy en la carpeta del proyecto.
**Solución:** `cd ITI-922-grupo6-hashes` y `python3 -m venv venv`.
