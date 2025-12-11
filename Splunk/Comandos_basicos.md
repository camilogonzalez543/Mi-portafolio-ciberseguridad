## 🔍 🟦 Comandos Básicos Adicionales de Splunk (SPL)

Este documento incluye comandos SPL adicionales, esenciales para analistas SOC, threat hunting y creación de dashboards.

---

### **lookup**
Cruza información con una tabla externa.
```
| lookup lista_bloqueo ip AS src_ip OUTPUT descripcion
```

### **transaction**
Agrupa eventos relacionados.
```
| transaction user startswith="login" endswith="logout"
```

### **join**
Une dos búsquedas.
```
| join user [ search index=auth action=success ]
```

### **tstats**
Interroga datos acelerados.
```
| tstats count from datamodel=Endpoint.Processes where Processes.process_name=* by host
```

### **regex**
Filtra mediante expresiones regulares.
```
| regex CommandLine="(encod|bypass|mimikatz)"
```

### **where**
Filtra usando condiciones avanzadas.
```
| where count > 50 AND like(user, "%admin%")
```

### **geostats**
Mapas geográficos.
```
| geostats count by src_ip
```

### **metadata**
Información rápida de hosts, sourcetypes, etc.
```
| metadata type=hosts
```

### **head**
Muestra las primeras líneas.
```
| index=windows | head 20
```

