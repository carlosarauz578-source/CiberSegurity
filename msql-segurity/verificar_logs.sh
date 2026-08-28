#!/bin/bash

LOG_DIR="/home/enri/CiberSegurity"
REPORTE="$LOG_DIR/verificacion_logs.txt"

echo "=== REPORTE DE VERIFICACIÓN DE LOGS ===" > $REPORTE
echo "Fecha: $(date)" >> $REPORTE
echo "" >> $REPORTE

for archivo in auditoria.log reportes.log reportes_md.log tor-ips.log cron_execution.log; do
    echo "Archivo: $archivo" >> $REPORTE
    if [ -f "$LOG_DIR/$archivo" ]; then
        echo "  - Tamaño actual: $(stat -c%s "$LOG_DIR/$archivo") bytes" >> $REPORTE
    else
        echo "  - No existe el archivo actual" >> $REPORTE
    fi

    if ls "$LOG_DIR/$archivo".*gz >/dev/null 2>&1; then
        echo "  - Copias rotadas:" >> $REPORTE
        ls -lh "$LOG_DIR/$archivo".*gz >> $REPORTE
    else
        echo "  - No hay copias rotadas" >> $REPORTE
    fi
    echo "" >> $REPORTE
done

echo "=== FIN DEL REPORTE ===" >> $REPORTE
