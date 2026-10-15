# Bitácora de uso de IA — Fiorella

Registro honesto del trabajo hecho con ayuda de IA (Claude Code) para mi parte
del proyecto (`login.py`). Incluye los errores que surgieron y cómo se
corrigieron.

| Fecha | Herramienta | Qué le pedimos | Qué respondió (resumen) | Qué verificamos o corregimos |
|-------|-------------|----------------|-------------------------|------------------------------|
| 2026-10-15 | Claude Code (Opus) | Montar la VM e instalar el entorno (Paso 1). | Creó la VM, instaló python3-venv, pip, git, sqlite3 y john; creó venv, instaló bcrypt y argon2-cffi, generó requirements.txt y .gitignore. | Verificamos las versiones instaladas: bcrypt 5.0.0, argon2-cffi 25.1.0. Commit y push correctos. |
| 2026-10-15 | Claude Code (Opus) | Verificar las APIs de bcrypt y argon2-cffi (regla 4). | Mostró que `bcrypt.gensalt(rounds=12)` es correcto y que `PasswordHasher` acepta time_cost/memory_cost/parallelism. | Confirmado ejecutando `help()`/`inspect.signature` dentro de la VM, no de memoria. |
| 2026-10-15 | Claude Code (Opus) | Verificar parámetros de Argon2id contra OWASP (regla 5). | OWASP recomienda **m=19456 KiB (19 MiB), t=2, p=1**. El "15 MiB" de nuestro documento NO aparece en la lista de OWASP. | Lo verificamos en la OWASP Password Storage Cheat Sheet (web oficial). Usamos 19456/2/1 y lo anotamos como corrección al documento del grupo. |
| 2026-10-15 | Claude Code (Opus) | Comportamiento de bcrypt con claves > 72 bytes. | bcrypt 5.0.0 **lanza ValueError** (ya no recorta en silencio como las 4.x). | Lo probamos con una clave de 73 bytes. Añadimos la función `validar_largo_bcrypt` con mensaje claro en español. |
| 2026-10-15 | Claude Code (Opus) | Escribir `login.py` (Paso 2). | Creó las funciones de hash/verificación, tabla SQLite, menú, getpass y tiempos con perf_counter. | Ejecutamos pruebas: registro, login correcto/incorrecto, usuario inexistente, clave muy larga. Todo pasó. |
| 2026-10-15 | Claude Code (Opus) | **Error detectado:** al probar con `python -I` dio "No module named 'login'". | La opción `-I` quita la carpeta actual del path de Python. | Corregido: se ejecuta sin `-I` por ser código propio del proyecto. |
| 2026-10-15 | Claude Code (Opus) | Usuarios de prueba (Paso 3). | Generó 9 usuarios; carla y gabriela con la misma clave; ivan con clave aleatoria vía `secrets`. | Verificamos que la opción 4 no falla si los usuarios ya existen (los omite). |
| 2026-10-15 | Claude Code (Opus) | Exportar hashes y verificar formato con John (Pasos 4). | Generó `exportados/usuarios_*.txt` en formato `usuario:hash`. La versión básica de john (apt) solo trae bcrypt. | Instalamos la versión **jumbo** (snap) y confirmamos que carga los 4 formatos: raw-md5, raw-sha256, bcrypt, argon2. |
| 2026-10-15 | Claude Code (Opus) | Pruebas finales y experimento de sal (Paso 5). | Mostró la tabla con SQLite y comparó carla vs gabriela. | Confirmado: MD5 idéntico (sin sal) pero bcrypt distinto (con sal). |
| 2026-10-15 | Claude Code (Opus) | Documentación (Paso 6): README, guía, bitácora, defensa. | Redactó los cuatro archivos en `docs/` y la sección mía del README. | Revisados por mí antes de la exposición. |

> **Nota de honestidad:** todo el código fue generado con ayuda de la IA, pero
> fue probado y verificado dentro de la VM antes de cada commit. Las fuentes
> externas (OWASP, APIs de las librerías) se consultaron en vez de asumir.
