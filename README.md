# AzureGWOpenVPN
.SYNOPSIS
     Converts ovpn base file from Azure OpenVPN Gateway and injects a client certificate properties in a new file
     
DESCRIPTION 
     Converts a Windows PFX certificates (PKCS#12) into PEM (PKCS#8) format for use with Azure OpenVPN Gateway and then
     injects the contentx (private key, public key) into the OpenVPN client file. 
     
PARAMETER PFXFile
     Path of the PFX file to be converted. Provide the full path to the PFX file (eg c:\certificates\mycert.pfx)
 
PARAMETER P2SZipFile
     Path to the downloaded ZIP file. This can be found at the P2S Connections blade of your Azure Virtual Network Gateway.
     
PARAMETER Passphrase
     Private key passphrase of your PFX file - optionally added for automation - script will ask securely if not specified

PARAMETER ovpnFile   
     OpenVPN file to be created

PARAMETER skipFileCreation
     Removes the requirement to have a ZIP file and only outputs the private and public key pairs of the pfx file
     
EXAMPLE
CreateOvpn.ps1 -PFXFile .\MyClient.pfx -P2SZipFile '.\P2SGW-OpenVPN.zip' 
    #normal usage, creates the openVPN profile for the user and asks for the password of the PFX
    
CreateOvpn.ps1 -PFXFile .\MyClient.pfx -Passphrase SecretPassword -P2SZipFile '.\P2SGW-OpenVPN.zip' -outfile MyClient.ovpn
    #creates the openVPN profile as MyClient.ovpn, does not ask for the password
    
CreateOvpn.ps1 -PFXFile .\MyClient.pfx -skipFileCreation $true
    #only displays the private public keypair of the certificate for manual copy
