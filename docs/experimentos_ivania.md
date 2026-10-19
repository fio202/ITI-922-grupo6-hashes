# Experimentos y ataques — Ivania

Esta es la parte práctica del proyecto (tema 7: hashes y contraseñas). Son
scripts que **importan** las funciones de `login.py` (de Fiorella) y no lo
modifican. Cada uno demuestra una propiedad distinta de las funciones hash.

> Todos los datos son contraseñas de prueba inventadas por el grupo. No se usó
> ningún dato real de terceros.

Los resultados completos están en la carpeta `resultados/` (archivos `.txt` y
los gráficos `.png`). Los números pueden variar un poco en cada corrida y
según la máquina, porque dependen de la velocidad del CPU.

---

## 1. Ataque de diccionario — `ataque_diccionario.py`

**Qué hace:** prueba cada palabra de `diccionario.txt` contra los hashes
guardados en `usuarios.db`, con los 4 esquemas.

- MD5 y SHA-256 **no usan sal**, así que se precalcula el hash de cada palabra
  una sola vez y se busca entre todos los usuarios (ataque de tabla
  precalculada / *rainbow table*). Es instantáneo.
- bcrypt y Argon2id **usan una sal distinta por usuario**, así que no se puede
  precalcular: hay que reintentar palabra por palabra contra cada usuario, y
  cada intento es lento a propósito. Por eso solo se atacó una muestra.

**Resultado (de `resultados/ataque.txt`):**

| Esquema | Velocidad del ataque | Usuarios rotos |
|---|---|---|
| MD5 | ~240.000 intentos/seg | 6 de 9 |
| SHA-256 | ~440.000 intentos/seg | 6 de 9 |
| bcrypt | ~1.6 intentos/seg | 3 de 4 (muestra) |
| Argon2id | ~18 intentos/seg | 3 de 4 (muestra) |

**Conclusión:** atacar bcrypt resultó ~154.000 veces más lento que atacar MD5.
Las contraseñas débiles (`123456`, `password`, `qwerty`, `costarica`…) cayeron
en todos los esquemas, pero en MD5/SHA al instante y en bcrypt/Argon2id a un
costo altísimo. Las contraseñas fuertes y la aleatoria (`ivan`) **no cayeron en
ningún esquema**: la fortaleza de la clave también importa.

## 2. Efecto de la sal — `experimento_sal.py`

**Qué hace:** `carla` y `gabriela` fueron registradas con la misma clave
(`costarica`). El script saca sus 4 hashes y los compara.

**Resultado:** el MD5 y el SHA-256 de las dos son **idénticos**; el bcrypt y el
Argon2id son **distintos**.

**Conclusión:** sin sal, dos usuarios con la misma clave tienen el mismo hash,
lo que delata claves repetidas y habilita tablas precalculadas. La sala
aleatoria por usuario (bcrypt, Argon2id) hace que la misma clave produzca
hashes diferentes.

## 3. Efecto avalancha — `efecto_avalancha.py`

**Qué hace:** hashea dos claves que difieren en un solo carácter
(`costarica1` vs `costarica2`) y cuenta cuántos **bits** del hash cambian.

**Resultado:** cambió cerca del **50 %** de los bits (64 de 128 en MD5; ~129 de
256 en SHA-256), con un cambio mínimo en la entrada.

**Conclusión:** un cambio pequeñísimo en la entrada altera medio hash. Por eso
no se puede "acercarse" al valor objetivo adivinando: el hash no conserva
ninguna pista de la entrada.

## 4. HMAC — `demo_hmac.py`

**Qué hace:** genera un HMAC-SHA256 de un mensaje con una llave secreta; luego
altera el mensaje y vuelve a verificar.

**Resultado:** con el mensaje intacto la verificación es **válida**; con el
mensaje alterado **falla**.

**Conclusión:** un hash solo da integridad (detecta cambios), pero cualquiera
puede recalcularlo. HMAC añade una llave secreta: da integridad **y**
autenticidad, porque sin la llave un atacante no puede fabricar un código
válido.

## 5. Gráficos — `graficos.py`

Genera `resultados/grafico_tiempos.png` (tiempo por hash, escala log) y
`resultados/grafico_intentos.png` (intentos por segundo). En esta VM: MD5 y
SHA-256 ~0.001 ms por hash; bcrypt ~1000 ms; Argon2id ~55 ms.

---

## Recomendación final (lo que une la práctica con la teoría)

Los números prueban por qué OWASP y NIST recomiendan **Argon2id con sal** para
guardar contraseñas en sistemas nuevos, y bcrypt como alternativa. Un hash
rápido (MD5, SHA-256) es justo lo que un atacante necesita. La lentitud y la
dureza de memoria de bcrypt/Argon2id son una defensa a propósito.

Parámetros usados en `login.py`, según la OWASP Password Storage Cheat Sheet:
Argon2id con 19 MiB de memoria, 2 iteraciones y paralelismo 1; bcrypt con
factor de costo 12.

## Fuentes

- OWASP, *Password Storage Cheat Sheet*.
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- IETF, *RFC 9106 — Argon2 Memory-Hard Function*.
  https://www.rfc-editor.org/rfc/rfc9106.html
- NIST, *SP 800-63B — Digital Identity Guidelines*.
  https://pages.nist.gov/800-63-3/sp800-63b.html
