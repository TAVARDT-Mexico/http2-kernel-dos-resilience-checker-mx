# HTTP/2 & Linux Kernel DoS Resilience Checker

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-mexico.github.io/http2-kernel-dos-resilience-checker-mx/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![RFC 7540](https://img.shields.io/badge/RFC-7540-blue.svg)](https://datatracker.ietf.org/doc/html/rfc7540)
[![RFC 9113](https://img.shields.io/badge/RFC-9113-blue.svg)](https://datatracker.ietf.org/doc/html/rfc9113)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Auditor automatizado de parámetros de red del kernel Linux, negociación del protocolo HTTP/2 (ALPN) y resiliencia ante ataques de Denegación de Servicio, desarrollado por **TAVARDT**, en cumplimiento con los requerimientos de la LFPDPPP y estándares internacionales ISO/IEC 27001.

Las infraestructuras web actuales afrontan continuas amenazas de denegación de servicio que explotan capas base del protocolo de red, tales como NoisyTCP y HTTP/2 Rapid Reset. Sin un ajuste exhaustivo de los sockets del sistema operativo y una validación rigurosa de protocolos, los servidores de origen sufren saturación de hilos y agotamiento de interfaces ante cargas asimétricas.

***

## Capacidades Principales y Arquitectura Defensiva

* **Auditoría Determinista de Parámetros del Kernel**: Analiza configuraciones en `/proc/sys/net/` frente a directrices de endurecimiento para neutralizar NoisyTCP, inundaciones SYN y sobrecargas de sockets.
* **Verificación Remota del Protocolo HTTP/2**: Examina la negociación ALPN sobre TLS en conexiones externas para garantizar el soporte formal de multiplexación binaria `h2`.
* **Detección de Filtración de Banners Informativos**: Identifica la exposición involuntaria de versiones de servidores y plataformas en las cabeceras `Server` y `X-Powered-By`.
* **Cero Dependencias Externas**: Desarrollado íntegramente con módulos estándar de Python (`socket`, `ssl`, `json`, `os`, `sys`), ofreciendo máxima velocidad sin librerías externas.
* **Integración Automatizada en Canales CI/CD**: Genera informes estructurados en JSON mediante la opción `-json` para monitorización continua en despliegues automatizados.

***

## Vectores de Riesgo e Impacto Operacional

Operar servidores de red con los parámetros predeterminados de Linux debilita las defensas ante ataques de saturación de tráfico. El sistema audita cuatro vectores de riesgo críticos:

* **NoisyTCP y Manipulación de Marcas Temporales**: Explotación de marcas de tiempo TCP para forzar desorden artificial de paquetes y congestionar las colas del kernel.
* **Agotamiento de Conexiones por Inundación SYN**: Bloqueo de las colas de conexión pendientes debido a la ausencia de cookies SYN y límites reducidos de backlog.
* **Degradación de Protocolo y Caída a Texto Plano**: Fallo al acordar `h2` mediante ALPN, forzando la degradación a canales HTTP/1.1 menos seguros y eficientes.
* **Reconocimiento Hostil mediante Cabeceras**: Exposición pública de versiones de software en cabeceras de respuesta, facilitando ataques dirigidos a vulnerabilidades documentadas.

***

## Instalación y Ejecución CLI

Ejecute auditorías locales en el kernel de Linux o inspecciones remotas de protocolo mediante comandos estándar de Python:

```bash
# Clonar el repositorio oficial
git clone https://github.com/TAVARDT-Mexico/http2-kernel-dos-resilience-checker-mx.git

# Acceder al directorio del proyecto
cd http2-kernel-dos-resilience-checker-mx

# Auditar parámetros locales de red del kernel Linux
python http2_kernel_dos_checker.py -kernel

# Auditar endpoint remoto para verificar HTTP/2 y cabeceras
python http2_kernel_dos_checker.py -host example.com -port 443

# Exportar reporte estructurado en JSON para canales CI/CD
python http2_kernel_dos_checker.py -host example.com -json
```

***

## Preguntas Técnicas Frecuentes

### ¿Cómo previene el ajuste de parámetros sysctl del kernel Linux los vectores de ataque NoisyTCP?

Desactivar las marcas de tiempo TCP impide la estimación de números de secuencia y el desorden deliberado de paquetes que saturan la pila de red. De forma complementaria, activar las cookies SYN y ampliar las colas de conexión mantiene la disponibilidad ante embates volumétricos de saturación.

### ¿Por qué resulta crucial la comprobación de la negociación ALPN para la seguridad de HTTP/2?

El protocolo ALPN garantiza que cliente y servidor acuerden la multiplexación de flujos de forma cifrada sobre TLS sin degradar hacia opciones en texto plano. Comprobar la selección de h2 certifica que los mecanismos modernos de control de flujo y ventanas de transmisión se aplican debidamente desde el inicio de la sesión.

### ¿De qué manera la exposición de cabeceras Server y X-Powered-By incrementa el riesgo de denegación de servicio?

Mostrar versiones exactas de las aplicaciones web permite a atacantes coordinar vectores de denegación dirigidos contra defectos de memoria específicos de dicha versión. Eliminar los banners informativos priva a las herramientas automáticas de rastreo de los datos necesarios para explotar debilidades concretas.

### ¿Cuál es la diferencia práctica entre ejecutar la auditoría local del kernel y una evaluación remota de red?

La auditoría local inspecciona los parámetros sysctl directamente en el sistema de archivos proc para validar el endurecimiento del sistema operativo anfitrión. En cambio, la auditoría remota analiza el apretón de manos TLS, el soporte ALPN y las cabeceras emitidas a través de la red sin necesidad de credenciales privilegiadas.

### ¿Puede implementarse la herramienta de resiliencia en cadenas automatizadas de integración continua CI/CD?

La utilidad de línea de comandos proporciona salida estructurada mediante la opción -json, lo que permite a las canalizaciones inspeccionar de forma automática las puntuaciones de conformidad. Los equipos de DevOps pueden evaluar estos datos para bloquear el despliegue de entornos que no alcancen los estándares exigidos de seguridad.

***

## Enlaces Útiles

* **Portal Corporativo:** https://ag.tavardt.com/mx/
* **Suite de Diagnósticos:** https://tools.tavardt.com/mx/
* **Contacto Técnico:** https://ag.tavardt.com/mx/contacto/

***

### Licencia
Distribuido bajo la Licencia MIT. Consulte [LICENSE](LICENSE) para obtener detalles completos.

***

© 2026 TAVARDT. Todos los derechos reservados.
