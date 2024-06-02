________________SSL_______________________
Key generation
keytool.exe -genkey -alias javabegin -keyalg RSA -keypass changeit -storepass changeit -keystore "c:\servers\glassfish4\glassfish\domains\domain1\config\keystore.jks"

Retrieving storage contents
keytool.exe -list -v -keystore "c:\servers\glassfish4\glassfish\domains\domain1\config\keystore.jks"
keytool.exe -list -v -keystore "c:\servers\glassfish4\glassfish\domains\domain1\config\cacerts.jks"


Exporting a certificate
keytool.exe -export -alias javabegin -storepass changeit -file "c:\\server.cer" -keystore "c:\servers\glassfish4\glassfish\domains\domain1\config\keystore.jks"


Importing a certificate
keytool.exe -import -v -trustcacerts -alias javabegin -file "c:\\server.cer" -keystore "c:\servers\glassfish4\glassfish\domains\domain1\config\cacerts.jks" -keypass changeit

Removing keys
keytool.exe -delete -v -keystore "c:\servers\glassfish4\glassfish\domains\domain1\config\cacerts.jks"  -alias javabegin 


Generating a CSR (Certificate Signing Request)
keytool.exe -certreq -alias javabegin -file "c:\\javabegin.csr" -keystore "c:\servers\glassfish4\glassfish\domains\domain1\config\cacerts.jks"
