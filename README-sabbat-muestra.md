# 🕵️‍♂️ `sabbat-muestra` - Inspector de Archivos Inteligente

> **"No todos los archivos son lo que parecen. `muestra` te lo revela."**

`sabbat-muestra` es una herramienta de línea de comandos avanzada para inspeccionar archivos con enfoque en **seguridad, metadatos e integridad**. Combina las funcionalidades de `ls`, `file`, `stat`, `sha256sum` y mucho más, con análisis forense básico integrado.

##  Características

- **Análisis de seguridad**: detecta SUID/SGID, permisos peligrosos, nombres sensibles y **secretos en texto claro**.
- **Metadatos contextuales**: 
  - Archivos de texto: líneas, encoding, secretos.
  - Imágenes: dimensiones, formato, modo de color.
  - Binarios ELF: versión del compilador.
- **Integridad criptográfica**: SHA256 por defecto, con opción para MD5/SHA1.
- **Soporte para enlaces simbólicos**: analiza el enlace o su destino.
- **Salida JSON**: ideal para integración en scripts y pipelines de CI/CD.
- **Dependencias opcionales**: funciona sin `chardet` o `Pillow`, pero mejora con ellos.

##  Instalación

```bash
# Clona el repositorio
git clone https://github.com/sababt-cloud/sabbat-utilidades.git
cd sabbat-utilidades

# Hazlo ejecutable y enlázalo en tu PATH
sudo cp sabbat-muestra /usr/local/bin/
sudo chmod +x /usr/local/bin/sabbat-muestra

# Opcional: instala dependencias para funcionalidades avanzadas
pip3 install chardet Pillow  # Para análisis de encoding e imágenes
