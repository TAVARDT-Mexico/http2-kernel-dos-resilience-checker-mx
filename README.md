# Hub de Hardening y Resiliencia DoS HTTP/2 y Kernel Linux

Especificación técnica corporativa de ingeniería defensiva y blueprints de infraestructura para mitigar vectores de saturación HTTP/2 Rapid Reset (CVE-2023-44487) y NoisyTCP, hardening de kernel Linux (sysctl) y verificación CLI determinista local.

## Alcance Técnico del Repositorio

Este repositorio proporciona plantillas de hardening probadas en producción y herramientas CLI deterministas:

1. **sysctl-hardening.conf:** Parámetros optimizados en `/proc/sys/net/ipv4` mitigando inundaciones SYN, ataques de timestamp NoisyTCP y agotamiento de sockets huérfanos.
2. **nginx-http2-hardened.conf:** Configuración de proxy inverso NGINX blindada imponiendo límites estrictos de concurrencia (`http2_max_concurrent_streams 64`) y rate limiting riguroso de tramas RST_STREAM.
3. **nftables-dos-protection.conf:** Reglas de filtrado de paquetes de Capa 4 descartando ráfagas anómalas TCP SYN y RST antes de la asignación de sockets en el kernel.
4. **docker-compose-hardened.yml:** Arquitectura de contenedores aislados aplicando límites de recursos (memoria, CPU, ulimits) a proxies web perimetrales.
5. **http2_kernel_dos_checker.py:** Utilidad CLI local determinista ejecutada con privilegios de sistema en el servidor para auditar directamente parámetros `/proc/sys` y verificar cumplimiento de RFCs.

> [!NOTE]
> La inspección activa del estado del kernel Linux y los parámetros de red requiere privilegios de sistema y debe ejecutarse directamente en el servidor mediante la herramienta CLI en Python. Las páginas web en entornos sandbox de navegador no pueden auditar parámetros del kernel host.

## Uso de la Herramienta CLI

Ejecute el script de auditoría determinista directamente en el host del servidor:

```bash
# 1. Descargar script de auditoria
curl -sO https://raw.githubusercontent.com/TAVARDT-Mexico/http2-kernel-dos-resilience-checker-mx/main/http2_kernel_dos_checker.py

# 2. Inspeccionar parametros locales del kernel Linux
sudo python3 http2_kernel_dos_checker.py -kernel

# 3. Exportar resultados en formato JSON
sudo python3 http2_kernel_dos_checker.py -kernel -json
```

## Gobernanza y Soberanía

* **Organización:** TAVARDT-Mexico
* **Jurisdicción:** Mexico
* **Cumplimiento de Estándares:** RFC 7540, RFC 9113, CVE-2023-44487, Arquitectura Zero Trust

Desarrollado por la División de Ciberseguridad e Infraestructura de **TAVARDT Mexico**. Todos los derechos reservados.
