# Instrucciones para subir Repositorios

La forma más simple es: inicializa Git en tu carpeta, crea un repositorio remoto en GitHub, y haz push.

## Opciones para VsCode

### Opción 1: desde la terminal de VS Code

Dentro de tu proyecto en VS Code:

```bash

git init
git add .
git commit -m "Primer commit"
git branch -M main
git remote add origin https://github.com/user/repo.git
git push -u origin main
```

Si GitHub te pide autenticación

Normalmente abrirá login por navegador. Si no, puedes usar:

- tu sesión de GitHub en VS Code
- o un Personal Access Token en vez de contraseña

### Opción 2: usando la interfaz de VS Code

1. Abre tu proyecto en VS Code.
2. Ve a la pestaña Source Control.
3. Pulsa Initialize Repository.
4. Haz stage de los archivos.
5. Escribe un mensaje de commit y confirma.
6. Pulsa Publish to GitHub o agrega el remoto manualmente.
7. Selecciona tu cuenta y publica.

Si el repo user/repo ya existe y está vacío

Usa estos comandos exactos:

```bash

git init
git add .
git commit -m "Subiendo proyecto inicial"
git branch -M main
git remote add origin https://github.com/user/repo.git
git push -u origin main
```

Si te da error de *“remote origin already exists”*. Usa:

```bash

git remote set-url origin https://github.com/sYncEros/Panoptico.git
git push -u origin main
```

Si te da error porque el repo remoto ya tiene archivos. Primero trae los cambios:

```bash

git pull origin main --allow-unrelated-histories
git push -u origin main
```

## Proceso paso a paso para Windows

Lo más probable es que no sea tu proyecto, sino la forma de iniciar sesión de Git desde VS Code. Haz esto, en este orden:

### Opción más fácil: autenticar VS Code con GitHub

1. En VS Code, presiona Ctrl+Shift+P
2. Escribe: GitHub: Sign in O también: Accounts: Sign in
3. Completa el login en el navegador
4. Vuelve a intentar el push

Si sigue fallando, usa HTTPS + token

GitHub ya no acepta contraseña normal en Git. Debes usar un Personal Access Token (PAT).

1. Crea un token en GitHub

Ve a:
    GitHub > Settings
    Developer settings
    Personal access tokens
    Tokens (classic) o Fine-grained tokens

Crea uno con permiso para repositorios.

1. Usa este remoto

En la terminal de VS Code:

```bash

git remote set-url origin https://github.com/sYncEros/Panoptico.git
git push -u origin main
```

Cuando pida credenciales:
    **Username:** tu usuario de GitHub
    **Password:** pega el token, no tu contraseña

Si quieres limpiar credenciales viejas
A veces falla porque Windows/macOS guardó una credencial incorrecta.

En Windows:
    Abre Administrador de credenciales
    Busca entradas de git:<https://github.com>
    Elimínalas
    Reintenta el push

Corre esto en la terminal:

```bash

git config --global user.name
git config --global user.email
```

Si están vacíos:

```bash

git config --global user.name "sYncEros"
git config --global user.email "tu-correo@example.com"
```

Alternativa más estable: usar SSH
Si HTTPS te sigue dando problemas, usa SSH. Es muy confiable para GitHub.

Ejemplo general:

```bash

ssh-keygen -t ed25519 -C "tu-correo@example.com"
```

Luego agregas la clave pública a GitHub y cambias el remoto a:

```bash

git remote set-url origin git@github.com:user/repo.git
```

Si quieres, te ayudo paso a paso con una de estas dos rutas:
    arreglar login con token
    configurar SSH

Si me pegas el mensaje exacto del error, te digo cuál es la solución correcta.

## Errores

### Error 403

Sí lograste llegar a GitHub, pero Git está usando credenciales incorrectas o sin permisos válidos para user/repo.

En tu caso, como el repo es user/repo y dice denied to user, lo más probable es una de estas 3 cosas:
    Git está usando una credencial vieja/corrupta
    Estás usando contraseña en vez de token
    Tu token no tiene permiso al repo

Solución rápida

Haz esto exacto.

### 1) Borra credenciales guardadas de GitHub

En Windows:
    Abre Administrador de credenciales
    Ve a Credenciales de Windows
    Borra todas las que sean de:
        git:<https://github.com>
        github.com

Luego cierra y abre VS Code.

### 2) Fuerza el remoto correcto

En la terminal de VS Code:

```bash
git remote -v
git remote set-url origin https://github.com/user/repo.git
git remote -v
```

### 3) Intenta push otra vez

```bash
git push -u origin main
```

Cuando pida credenciales:
    usuario: user
    contraseña: tu token PAT, no tu contraseña de GitHub

Si no tienes token, crea uno

Crea un Personal Access Token en GitHub con permisos de repositorio.

- Si usas fine-grained token, dale acceso a:
    repositorio: repo
    permisos de Contents: Read and write

- Si usas classic token, normalmente incluye:
    repo

Verifica si el problema es de credenciales o de permisos reales
Prueba abrir en el navegador, con tu sesión de GitHub:
    el repo user/repo
    y confirma que puedes ver/configurar el repo normalmente

Si el repo existe en tu cuenta, entonces casi seguro es credencial mala.

### Opción más limpia: usar GitHub CLI

Si tienes gh instalado:

```bash

gh auth login
```

Elige:
    GitHub.com
    HTTPS
    Login with a web browser

Luego:

```bash

gh auth setup-git
git push -u origin main
```

Eso suele arreglar el problema de autenticación en VS Code.
Alternativa recomendada: SSH

Si HTTPS sigue dando 403, cambia a SSH. Es muy estable.
Genera clave SSH

```bash

ssh-keygen -t ed25519 -C "tu-correo@example.com"
```

Inicia el agente y agrega la clave

```bash

eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

Muestra la clave pública

```bash

cat ~/.ssh/id_ed25519.pub
```

Copia eso y agrégalo en GitHub: Settings > SSH and GPG keys > New SSH key
Cambia el remoto

```bash

git remote set-url origin git@github.com:sYncEros/Panoptico.git
git push -u origin main
```

Lo que yo haría en tu lugar
    borrar credenciales guardadas
    crear un PAT nuevo
    hacer push por HTTPS con token
    si molesta otra vez, pasar a SSH

Si quieres, te doy el paso a paso exacto para Windows y te voy diciendo qué botón tocar.
O pégame la salida de:

```bash

git remote -v
git branch
git config --global user.name
git config --global user.email
```

y te digo exactamente qué corregir.

## Error: remote origin already exists

El problema es claro: tu remoto origin sigue apuntando a repoOld, no a repoNew.

Tú intentaste agregar:

```bash

https://github.com/user/repoNew.git
```

pero como origin ya existía, Git no lo cambió. Por eso cuando haces push sigue intentando esto:

```bash

https://github.com/user/repoOld.git/
```

**Solución:** Cambia la URL del remoto existente:

```bash

git remote set-url origin https://github.com/user/repoNew.git
```

Luego verifica:

```bash

git remote -v
```

Debe salir algo como:

```bash
origin  https://github.com/user/repoNew.git (fetch)
origin  https://github.com/user/repoNew.git (push)
```

Después haz push:

```bash

git push -u origin main
```

Si repoNew todavía no existe en GitHub

Entonces primero tienes que crear el repositorio en GitHub con ese nombre:
    user/repoNew

Y luego volver a correr:

```bash

git remote set-url origin https://github.com/user/repoNew.git
git push -u origin main
```

Si quieres empezar limpio

También puedes borrar el remoto y volverlo a crear:

```bash

git remote remove origin
git remote add origin https://github.com/user/repoNew.git
git push -u origin main
```
