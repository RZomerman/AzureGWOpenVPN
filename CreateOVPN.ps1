
# ==================== #
# Create CreateOvpn.ps1 # Copyright StudioGraphic, AzureInfra.com Inc, 2016, 2017, 2018
#
# PFX to Private/Public key are from: https://github.com/mongodb/support-tools/blob/master/ssl-windows/Convert-PfxToPem.ps1
# Convert-PfxToPem.ps1 # Copyright MongoDB, Inc, 2016, 2017
# ==================== #

<#
   .SYNOPSIS
     Converts ovpn base file from Azure OpenVPN Gateway and injects a client certificate properties in a new file
   .DESCRIPTION 
     Converts a Windows PFX certificates (PKCS#12) into PEM (PKCS#8) format for use with Azure OpenVPN Gateway and then
     injects the contentx (private key, public key) into the OpenVPN client file. 
   .PARAMETER PFXFile
     Path of the PFX file to be converted. Provide the full path to the PFX file (eg c:\certificates\mycert.pfx)
   .PARAMETER P2SZipFile
     Path to the downloaded ZIP file. This can be found at the P2S Connections blade of your Azure Virtual Network Gateway.
   .PARAMETER Passphrase
     Private key passphrase of your PFX file - optionally added for automation - script will ask securely if not specified
    .PARAMETER ovpnFile
     OpenVPN file to be created
    .PARAMETER skipFileCreation
     Removes the requirement to have a ZIP file and only outputs the private and public key pairs of the pfx file
    
    .EXAMPLE
    .\CreateOvpn.ps1 -PFXFile .\MyClient.pfx -P2SZipFile '.\P2SGW-OpenVPN.zip' 
    #normal usage, creates the openVPN profile for the user and asks for the password of the PFX
    
    .\CreateOvpn.ps1 -PFXFile .\MyClient.pfx -Passphrase SecretPassword -P2SZipFile '.\P2SGW-OpenVPN.zip' -outfile MyClient.ovpn
    #creates the openVPN profile as MyClient.ovpn, does not ask for the password
    
    .\CreateOvpn.ps1 -PFXFile .\MyClient.pfx -skipFileCreation $true
    #only displays the private public keypair of the certificate for manual copy
#>

#
# DISCLAIMER
#
# Please note: all tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, 
# including, but not limited to their installation, use, or performance. We disclaim any and all warranties, either 
# express or implied, including but not limited to any warranty of noninfringement, merchantability, and/ or fitness 
# for a particular purpose. We do not warrant that the technology will meet your requirements, that the operation 
# thereof will be uninterrupted or error-free, or that any errors will be corrected.
#
# Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough 
# testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
#
# You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
#
#
# LICENSE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with 
# the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on 
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the 
# specific language governing permissions and limitations under the License.
#

Param(
     [Parameter(Mandatory=$true, Position=1, HelpMessage="Enter the PFX certificate file you wish to convert.")]
     [string] $PFXFile,

     [Parameter(Mandatory=$false, HelpMessage="Enter the PFX certificate passphrase.")]
     [string] $Passphrase = '',

     [Parameter(Mandatory=$false, HelpMessage="Enter the path to the downloaded P2S zip file")]
     [string] $P2SZipFile,

     [Parameter(Mandatory=$false, HelpMessage="Enter the filename for the ovpn profile to create")]
     [string] $outfile,

     [Parameter(Mandatory=$false, HelpMessage="Show only public/private keypairs")]
     [boolean] $skipFileCreation
)

Add-Type @'
   using System;
   using System.Security.Cryptography;
   using System.Security.Cryptography.X509Certificates;
   using System.Collections.Generic;
   using System.Text;

   public class AzureNetwork_Utils
   {
      public const int Base64LineLength = 64;

      private static byte[] EncodeInteger(byte[] value)
      {
         var i = value;

         if (value.Length > 0 && value[0] > 0x7F)
         {
            i = new byte[value.Length + 1];
            i[0] = 0;
            Array.Copy(value, 0, i, 1, value.Length);
         }

         return EncodeData(0x02, i);
      }

      private static byte[] EncodeLength(int length)
      {
         if (length < 0x80)
            return new byte[1] { (byte)length };

         var temp = length;
         var bytesRequired = 0;
         while (temp > 0)
         {
            temp >>= 8;
            bytesRequired++;
         }

         var encodedLength = new byte[bytesRequired + 1];
         encodedLength[0] = (byte)(bytesRequired | 0x80);

         for (var i = bytesRequired - 1; i >= 0; i--)
            encodedLength[bytesRequired - i] = (byte)(length >> (8 * i) & 0xff);

         return encodedLength;
      }

      private static byte[] EncodeData(byte tag, byte[] data)
      {
         List<byte> result = new List<byte>();
         result.Add(tag);
         result.AddRange(EncodeLength(data.Length));
         result.AddRange(data);
         return result.ToArray();
      }
       
      public static string RsaPrivateKeyToPem(RSAParameters privateKey)
      {
         // Version: (INTEGER)0 - v1998
         var version = new byte[] { 0x02, 0x01, 0x00 };

         // OID: 1.2.840.113549.1.1.1 - with trailing null
         var encodedOID = new byte[] { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

         List<byte> privateKeySeq = new List<byte>();

         privateKeySeq.AddRange(version);
         privateKeySeq.AddRange(EncodeInteger(privateKey.Modulus));
         privateKeySeq.AddRange(EncodeInteger(privateKey.Exponent));
         privateKeySeq.AddRange(EncodeInteger(privateKey.D));
         privateKeySeq.AddRange(EncodeInteger(privateKey.P));
         privateKeySeq.AddRange(EncodeInteger(privateKey.Q));
         privateKeySeq.AddRange(EncodeInteger(privateKey.DP));
         privateKeySeq.AddRange(EncodeInteger(privateKey.DQ));
         privateKeySeq.AddRange(EncodeInteger(privateKey.InverseQ));

         List<byte> privateKeyInfo = new List<byte>();
         privateKeyInfo.AddRange(version);
         privateKeyInfo.AddRange(encodedOID);
         privateKeyInfo.AddRange(EncodeData(0x04, EncodeData(0x30, privateKeySeq.ToArray())));

         StringBuilder output = new StringBuilder();

         var encodedPrivateKey = EncodeData(0x30, privateKeyInfo.ToArray());
         var base64Encoded = Convert.ToBase64String(encodedPrivateKey, 0, (int)encodedPrivateKey.Length);
         output.AppendLine("-----BEGIN PRIVATE KEY-----");

         for (var i = 0; i < base64Encoded.Length; i += Base64LineLength)
            output.AppendLine(base64Encoded.Substring(i, Math.Min(Base64LineLength, base64Encoded.Length - i)));

         output.Append("-----END PRIVATE KEY-----");
         return output.ToString();
      }

      public static string PfxCertificateToPem(X509Certificate2 certificate)
      {
         var certBase64 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));

         var builder = new StringBuilder();
         builder.AppendLine("-----BEGIN CERTIFICATE-----");

         for (var i = 0; i < certBase64.Length; i += AzureNetwork_Utils.Base64LineLength)
            builder.AppendLine(certBase64.Substring(i, Math.Min(AzureNetwork_Utils.Base64LineLength, certBase64.Length - i)));

         builder.Append("-----END CERTIFICATE-----");
         return builder.ToString();
      }
   }
'@


write-host ""
write-host ""
write-host "                               _____        __                                " -ForegroundColor Green
write-host "     /\                       |_   _|      / _|                               " -ForegroundColor Yellow
write-host "    /  \    _____   _ _ __ ___  | |  _ __ | |_ _ __ __ _   ___ ___  _ __ ___  " -ForegroundColor Red
write-host "   / /\ \  |_  / | | | '__/ _ \ | | | '_ \|  _| '__/ _' | / __/ _ \| '_ ' _ \ " -ForegroundColor Cyan
write-host "  / ____ \  / /| |_| | | |  __/_| |_| | | | | | | | (_| || (_| (_) | | | | | |" -ForegroundColor DarkCyan
write-host " /_/    \_\/___|\__,_|_|  \___|_____|_| |_|_| |_|  \__,_(_)___\___/|_| |_| |_|" -ForegroundColor Magenta
write-host "                                                                              "
write-host "This script merges the OpenVpn zip file with a custom PFX file to generate a full OpenVPN file" -ForegroundColor Green

If ((!($skipFileCreation)) -and (!($P2SZipFile)) ){
    write-host "No path to zip file entered, please use -P2SZipFile" -ForegroundColor Red
    exit
}



#Validating if the supplied file has a pfx extension
If (!($PFXFile -match '.+?pfx$')) {
    write-host "No PFX file specified, please specify a PFX file to be merged into the OpenVPN Client file" -ForegroundColor Red
    Exit
}

#requesting the password for the pfx file - if not specified 
If (!($Passphrase)) {
    write-host "Please enter the password for the PFX file" -ForegroundColor Yellow
    $SecurePassphrase = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassphrase)
    $Passphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

#Function to extract the zip file and reach to the downloaded vpnconfig.ovpn
Function ExtractZip($ovpnZipFile){
    Expand-Archive $ovpnZipFile -destinationPath $env:tmp -force
    copy-Item -path ($env:tmp + '\OpenVPN\*') -destination ((Get-Location).path)  -force
    If (-not(test-path (((Get-Location).path) + '\vpnconfig.ovpn'))){
        Write-Warning "Cannot find OVPN Config file.. "
        Exit
    }Else{
        $OvpnFile=(((Get-Location).path) + '\vpnconfig.ovpn')
        return $OvpnFile
    }
}

#Fix for .\ file load in certificate
If ($PFXFile[0] -eq '.'){
    $PFXFile=((Get-Item -Path ".\").FullName + $PFXFile.Substring(1))
}

#Extracting the private and public keys from the input certificate
try
{
   if (-not ($cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($PFXFile, $Passphrase, 'Exportable')))
   {
      Write-Warning "Unable to load certificate $PFXFile"
      Exit
   }
}
catch
{
   Write-Warning "Unable to load certificate $PFXFile - $($_.Exception.Message)"
   Exit
}

if (-not $cert.HasPrivateKey) 
{
   Write-Warning "No private key present for $($cert.SubjectName.Name)"
   Exit
}

if (-not $cert.PrivateKey.CspKeyContainerInfo.Exportable)
{
   Write-Warning "Cannot find exportable private key for $($cert.SubjectName.Name)"
   Exit
}


$result = [AzureNetwork_Utils]::PfxCertificateToPem($cert)
$PublicKey=$result
If (-not ($PublicKey)) {
    Write-Warning "Cannot find exportable Public key"
    Exit
}
Write-host " -Retrieved public certificate details" -foregroundcolor Green


$parameters = ([Security.Cryptography.RSACryptoServiceProvider] $cert.PrivateKey).ExportParameters($true)
$PrivateKey += "`r`n" + [AzureNetwork_Utils]::RsaPrivateKeyToPem($parameters);

If (-not ($PrivateKey)) {
    Write-Warning "Cannot find exportable Private key"
    Exit
}
Write-host " -Retrieved private certificate details" -foregroundcolor Green

If ($skipFileCreation) {
    Write-host "<<<<Certificate Public Key>>>>" -ForegroundColor Green
    write-host $PublicKey
    write-host ""
    write-host "<<<<Certificate Private Key>>>>" -ForegroundColor Green 
    Write-host $PrivateKey
    write-host ""
    write-host "Skipping file creation..." -ForegroundColor Yellow
    Exit
}

If (!($skipFileCreation)) {
    #Extracting the zip file and injecting the private and public keys
    try 
    {
        Write-host " -Extracting P2S zip file.." -foregroundcolor Green
        $basefile=ExtractZip($P2SZipFile)
        $ovpnValue=Get-Content $basefile
        #After the certificate has been extracted, we need inject the private and public keys in the ovpn file
        $PublicKeyLine=($ovpnValue | Select-String 'CLIENTCERTIFICATE').LineNumber
        $ovpnValue[$PublicKeyLine-1] = $PublicKey
        $PrivateKeyLine=($ovpnValue | Select-String 'PRIVATEKEY').LineNumber
        $ovpnValue[$PrivateKeyLine-1] = $PrivateKey

        Write-host " -Created the ovpn profile" -foregroundcolor Green
        #and save a new file with these injected parameters
        If ($outfile) {
            Set-Content -Path $outfile -Value $ovpnValue    
        }Else{
            $outfile=((Get-Location).path + '\P2SOpenVPN.ovpn')
            Set-Content -Path $outfile -Value $ovpnValue    
            
        }
        Write-host "New ovpn file saved:" $outfile -foregroundcolor Green
        Write-host "Use this file in the OpenVPN client: https://openvpn.net/index.php/open-source/downloads.html" -foregroundcolor Yellow
        Write-host "For Windows users, please copy the $outfile to c:\program files\openvpn\config" -foregroundcolor Yellow
    }
    catch
    {
    Write-Warning "Unable to create openVPNfile - $($_.Exception.Message)"
    Exit
    }
}