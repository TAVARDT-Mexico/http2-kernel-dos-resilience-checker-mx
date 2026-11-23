# Auditor de Resiliencia HTTP/2 & Caída de Kernel Linux - TAVARDT México

> Auditoría de Resiliencia contra NoisyTCP, Rapid Reset (CVE-2023-44487) y Blindaje de Servidores Web

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-mexico.github.io/http2-kernel-dos-resilience-checker-mx/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS Linux](https://img.shields.io/badge/Security-CIS%20Linux%20%7C%20RFC%209113-red.svg)](https://www.cisecurity.org/)

## Visión General de Arquitectura y Resiliencia HTTP/2 & Kernel Linux

La estabilidad y resiliencia de servidores corporativos de alta demanda dependen de la sincronía entre la pila de transporte TCP del kernel Linux y los motores de multiplexación HTTP/2.

Dos clases críticas de amenazas afectan sistemas no protegidos:
1. **Vulnerabilidad NoisyTCP en el Kernel Linux:** Paquetes TCP anómalos fuera de orden fuerzan una asignación desordenada de memoria en el kernel, provocando la caída de Nginx, Apache y SSH sin autenticación.
2. **Abuso de Rapid Reset en HTTP/2 (CVE-2023-44487):** Ráfagas masivas de solicitudes canceladas de inmediato con tramas `RST_STREAM` saturan descriptores de archivos y capacidad de procesamiento.

Este repositorio proporciona una aplicación web interactiva que se ejecuta 100% en el navegador y un escáner CLI en Python con biblioteca estándar para auditar hosts locales y remotos.

## Aplicación Web Interactiva

Acceda a la herramienta online y audite su servidor en tiempo real:

* [https://tavardt-mexico.github.io/http2-kernel-dos-resilience-checker-mx/](https://tavardt-mexico.github.io/http2-kernel-dos-resilience-checker-mx/)

La aplicación evalúa 5 etapas de seguridad, calcula el índice de resiliencia (0 a 100), genera diagnósticos de riesgo y proporciona configuraciones defensivas listas para producción.

## Utilización del Escáner CLI (Python)

El repositorio incluye el script `http2_kernel_dos_checker.py`, desarrollado exclusivamente con la biblioteca estándar de Python:

```bash
# Auditar parametros locales de kernel contra NoisyTCP
python3 http2_kernel_dos_checker.py --kernel

# Auditar servidor remoto (negociacion ALPN h2, TLS y cabeceras)
python3 http2_kernel_dos_checker.py --host su-servidor.com --port 443

# Ejecutar auditoria en formato JSON para CI/CD
python3 http2_kernel_dos_checker.py --host su-servidor.com --json
```

## Controles Arquitectónicos y Mitigaciones Defensivas

* **Kernel Linux (/etc/sysctl.conf):** Configuración de `net.ipv4.tcp_syncookies = 1`, desactivación de `net.ipv4.tcp_timestamps = 0` para contener NoisyTCP, ajuste de buffers (`tcp_rmem`, `tcp_wmem`) y `somaxconn = 4096`.
* **Nginx (nginx.conf):** Supresión de firmas (`server_tokens off`), límite de streams simultáneos (`http2_max_concurrent_streams 100`) y zonas de tasa (`limit_req_zone`) contra abusos de `RST_STREAM`.
* **Apache HTTP Server (httpd.conf):** Ocultación de cabeceras (`ServerTokens Prod`, `ServerSignature Off`), restricción de multiplexación via `mod_http2` (`H2MaxSessionStreams 100`) y timeouts con `mod_reqtimeout`.
* **Perímetro de Borde:** Terminación TLS gestionada con Cloudflare WAF y aislamiento total de la IP de origen.

## Portales Oficiales

* **Portal Corporativo TAVARDT México:** [https://ag.tavardt.com/mx/](https://ag.tavardt.com/mx/)
* **Servicios de Ciberseguridad:** [https://ag.tavardt.com/mx/ciberseguridad/](https://ag.tavardt.com/mx/ciberseguridad/)
* **Hub de Herramientas:** [https://tools.tavardt.com/mx/](https://tools.tavardt.com/mx/)
* **Organización GitHub:** [https://github.com/TAVARDT-Mexico](https://github.com/TAVARDT-Mexico)

## Licencia

Distribuido bajo licencia MIT. Consulte el archivo `LICENSE` para más información.
