#!/bin/sh

echo "=== Backup service started at $(date) ===" | tee -a /backup/backup.log
sleep 30

while true; do
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  BACKUP_DIR="/backup/${TIMESTAMP}"
  SQL_FILE="${BACKUP_DIR}/backup.sql"
  DUMP_FILE="${BACKUP_DIR}/backup.dump"

  echo "--- Starting backup at $(date) ---" | tee -a /backup/backup.log

  # Crear directorio para este backup
  mkdir -p $BACKUP_DIR

  # Backup 1: SQL (formato texto, legible)
  echo "Creating SQL backup..." | tee -a /backup/backup.log
  if pg_dump -h db_postgres -U ${POSTGRES_USER:-postgres} -d ${POSTGRES_DB:-mydb} --clean --if-exists > $SQL_FILE 2>>/backup/backup.log; then
    SQL_SIZE=$(du -h $SQL_FILE | cut -f1)
    echo "✓ SQL backup OK - Size: $SQL_SIZE" | tee -a /backup/backup.log
    SQL_SUCCESS=1
  else
    echo "✗ SQL backup FAILED" | tee -a /backup/backup.log
    SQL_SUCCESS=0
  fi

  # Backup 2: DUMP (formato custom, comprimido y robusto)
  echo "Creating DUMP backup..." | tee -a /backup/backup.log
  if pg_dump -h db_postgres -U ${POSTGRES_USER:-postgres} -d ${POSTGRES_DB:-mydb} -Fc -f $DUMP_FILE 2>>/backup/backup.log; then
    DUMP_SIZE=$(du -h $DUMP_FILE | cut -f1)
    echo "✓ DUMP backup OK - Size: $DUMP_SIZE" | tee -a /backup/backup.log
    DUMP_SUCCESS=1
  else
    echo "✗ DUMP backup FAILED" | tee -a /backup/backup.log
    DUMP_SUCCESS=0
  fi

  # Verificar integridad del dump
  if [ $DUMP_SUCCESS -eq 1 ]; then
    echo "Verifying DUMP integrity..." | tee -a /backup/backup.log
    if pg_restore -h db_postgres -U ${POSTGRES_USER:-postgres} -d ${POSTGRES_DB:-mydb} --list $DUMP_FILE > /dev/null 2>&1; then
      echo "✓ DUMP integrity verified" | tee -a /backup/backup.log
    else
      echo "⚠ DUMP integrity check failed" | tee -a /backup/backup.log
    fi
  fi

  # Crear archivo de metadata
  echo "Backup Date: $(date)" > ${BACKUP_DIR}/backup_info.txt
  echo "Database: ${POSTGRES_DB:-mydb}" >> ${BACKUP_DIR}/backup_info.txt
  echo "SQL File: backup.sql (${SQL_SIZE:-N/A})" >> ${BACKUP_DIR}/backup_info.txt
  echo "DUMP File: backup.dump (${DUMP_SIZE:-N/A})" >> ${BACKUP_DIR}/backup_info.txt
  if [ $SQL_SUCCESS -eq 1 ]; then
    echo "SQL Status: SUCCESS" >> ${BACKUP_DIR}/backup_info.txt
  else
    echo "SQL Status: FAILED" >> ${BACKUP_DIR}/backup_info.txt
  fi
  if [ $DUMP_SUCCESS -eq 1 ]; then
    echo "DUMP Status: SUCCESS" >> ${BACKUP_DIR}/backup_info.txt
  else
    echo "DUMP Status: FAILED" >> ${BACKUP_DIR}/backup_info.txt
  fi

  # Resumen
  if [ $SQL_SUCCESS -eq 1 ] && [ $DUMP_SUCCESS -eq 1 ]; then
    echo "✓✓ Full backup completed successfully - $(date)" | tee -a /backup/backup.log
  elif [ $SQL_SUCCESS -eq 1 ] || [ $DUMP_SUCCESS -eq 1 ]; then
    echo "⚠ Partial backup completed - $(date)" | tee -a /backup/backup.log
  else
    echo "✗✗ Backup FAILED completely - $(date)" | tee -a /backup/backup.log
  fi

  # Rotación: mantener solo los últimos 7 backups
  echo "Running backup rotation..." | tee -a /backup/backup.log
  cd /backup
  ls -t | grep -E '^[0-9]{8}_[0-9]{6}$' | tail -n +8 | xargs -r rm -rf
  REMAINING=$(ls -d [0-9]*_[0-9]* 2>/dev/null | wc -l)
  echo "Backups retained: $REMAINING" | tee -a /backup/backup.log

  echo "Next backup in 24 hours..." | tee -a /backup/backup.log
  echo "========================================" | tee -a /backup/backup.log
  sleep 86400
done
