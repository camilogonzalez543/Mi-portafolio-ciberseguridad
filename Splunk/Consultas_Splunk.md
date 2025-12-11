## 📊 Ejemplos de consultas Splunk
### **Detección de uso de herramientas administrativas fuera de horario**
```
index=windows EventCode=4688
| search (New_Process_Name="*psexec*" OR New_Process_Name="*wmic*" OR New_Process_Name="*powershell*")
| eval hour=strftime(_time,"%H")
| where hour < 6 OR hour > 20
| table _time, user, host, New_Process_Name, CommandLine
```
### **Detección de Mimikatz**
```
index=windows CommandLine="*sekurlsa*" OR CommandLine="*mimikatz*"
| table _time, host, user, CommandLine
```

### **Procesos sospechosos ejecutados en Windows**
```
index=windows EventCode=4688 CommandLine="*powershell*" OR CommandLine="*encoded*"
| table _time, user, New_Process_Name, CommandLine
```

### **PowerShell con parámetros maliciosos**
```
index=windows EventCode=4688 New_Process_Name="*powershell*"
| search CommandLine="*encod*" OR CommandLine="*bypass*" OR CommandLine="*nop*"
| table _time, user, New_Process_Name, CommandLine, parent_process_name, host
```

### **Creación de cuentas locales**
```
index=windows EventCode=4720
| table _time, user, Account_Name, host, Logon_ID
```

### **Ejecutables desde ubicaciones anómalas**
```
index=windows EventCode=4688
| regex New_Process_Name="(AppData|Temp|Downloads)"
| table _time, user, New_Process_Name, CommandLine
```

### 🌐 Tráfico de red sospechoso

### **IPs con múltiples fallos de autenticación**
```
index=* (fail* OR invalid*)
| stats count by src_ip, user
| where count > 10
| sort - count
```

### **Primer inicio de sesión desde un país inusual**
```
index=firewall
| iplocation src_ip
| stats earliest(_time) as first_login by user, Country
| sort first_login
```
