# Defensa — Fiorella (`login.py`)

Explicación sencilla de cada función y preguntas probables del profesor.

---

## Qué hace cada función de `login.py`

**Base de datos**
- `conectar(ruta_bd)` → abre `usuarios.db` y crea la tabla `usuarios` si no
  existe. La columna `usuario` es UNIQUE (no se repite).

**Funciones de hash** (convierten la clave en su "huella")
- `hash_md5(clave)` → MD5 en hexadecimal, **sin sal**.
- `hash_sha256(clave)` → SHA-256 en hexadecimal, **sin sal**.
- `hash_bcrypt(clave)` → bcrypt con `rounds=12`; la sal va dentro del hash.
- `hash_argon2(clave)` → Argon2id con los parámetros de OWASP; la sal va dentro.
- `validar_largo_bcrypt(clave)` → lanza error si la clave pasa de 72 bytes.
- `generar_clave_aleatoria(largo)` → clave aleatoria segura con `secrets`.

**Funciones de verificación** (devuelven True/False)
- `verificar_md5/sha256(clave, hash)` → rehashean y comparan con
  `hmac.compare_digest` (comparación en tiempo constante).
- `verificar_bcrypt(clave, hash)` → `bcrypt.checkpw`, lee la sal del propio hash.
- `verificar_argon2(clave, hash)` → `PasswordHasher.verify`, captura
  `VerifyMismatchError` cuando la clave no coincide.

**Operaciones del sistema**
- `registrar_usuario(usuario, clave)` → guarda la clave con los 4 hashes.
  Devuelve False si el usuario ya existe.
- `iniciar_sesion(usuario, clave)` → verifica con los 4 esquemas y mide el
  tiempo de cada uno con `time.perf_counter`.
- `listar_usuarios()` → devuelve todos los usuarios con sus 4 hashes.
- `cargar_usuarios_prueba()` → registra 9 usuarios de ejemplo.
- `exportar_hashes()` → escribe `exportados/usuarios_*.txt` (formato John).
- `main()` → menú de consola. Está bajo `if __name__ == "__main__"` para que el
  archivo se pueda **importar** sin que aparezca el menú.

---

## 10 preguntas probables en la defensa

**1. ¿Por qué MD5 es malo para contraseñas?**
Por dos razones: es **muy rápido** (un atacante prueba miles de millones por
segundo) y en mi programa lo uso **sin sal**, así que dos claves iguales dan el
mismo hash y sirven tablas precalculadas (rainbow tables). Además está roto para
colisiones.

**2. ¿Dónde queda guardada la sal en bcrypt?**
Dentro del propio hash. En `$2b$12$` + 22 caracteres, esos 22 caracteres **son
la sal** (16 bytes). Por eso no necesito una columna aparte: `checkpw` la lee de
ahí para verificar.

**3. ¿Qué significa `rounds=12` en bcrypt?**
Es el "costo". El número real de iteraciones es **2^12 = 4096**. Cada +1 duplica
el trabajo. 12 hace que cada hash tarde cientos de milisegundos, lo que frena
los ataques por fuerza bruta.

**4. ¿Qué hace `getpass`?**
Lee la contraseña **sin mostrarla** en pantalla (no se ve ni con asteriscos),
para que nadie la lea por encima del hombro ni quede en el historial visible.

**5. ¿Por qué usas `hmac.compare_digest` en vez de `==`?**
Compara en **tiempo constante**: tarda lo mismo aunque los textos difieran en el
primer carácter o en el último. Con `==` normal, un atacante podría medir el
tiempo y deducir cuántos caracteres acertó (ataque de temporización).

**6. ¿Qué es Argon2id y por qué es el más recomendado?**
Es un algoritmo "memory-hard": además de tiempo, exige **mucha memoria RAM**
(19 MiB en mi config). Eso hace carísimo atacarlo con GPUs o hardware
especializado. OWASP lo recomienda como primera opción.

**7. ¿De dónde salen los parámetros de Argon2id (19456, 2, 1)?**
De la **OWASP Password Storage Cheat Sheet**: mínimo 19 MiB (19456 KiB), 2
iteraciones y paralelismo 1. Nuestro documento decía "15 MiB", pero eso no
aparece en OWASP, así que lo corregí a 19 MiB.

**8. ¿Qué pasa si la contraseña tiene más de 72 bytes en bcrypt?**
bcrypt solo procesa los primeros **72 bytes**. La versión 5.0.0 que uso **lanza
un error** en vez de recortar en silencio. Mi programa lo valida antes y muestra
un mensaje claro. Ojo: una "ñ" o una tilde ocupan 2 bytes.

**9. Si dos usuarios tienen la misma contraseña, ¿se nota?**
Con MD5/SHA-256 **sí** (hash idéntico), por eso son inseguros. Con bcrypt y
Argon2id **no**, porque cada uno recibe una sal aleatoria distinta. Lo demuestro
con carla y gabriela: mismo MD5, distinto bcrypt.

**10. ¿Por qué `if __name__ == "__main__"`?**
Para que el menú solo corra cuando ejecuto `python login.py`. Si otro script
hace `import login` (mis compañeros, para los ataques), puede usar mis funciones
**sin** que se abra el menú.

---

### Preguntas extra posibles

**¿Por qué guardas el hash y no la contraseña?**
Porque el hash es de una sola vía: si roban la base, no pueden leer las claves
directamente. Al iniciar sesión se rehashea lo que escribe el usuario y se
comparan los hashes.

**¿Qué es la sal y para qué sirve?**
Es un valor aleatorio que se mezcla con la clave antes de hashear. Hace que la
misma contraseña dé hashes distintos y anula las tablas precalculadas.
