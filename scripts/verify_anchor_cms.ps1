param([Parameter(Mandatory=$true)][string]$Directory,
      [Parameter(Mandatory=$true)][string]$ExpectedBundleSha256,
      [Parameter(Mandatory=$true)][string]$Receipt)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$bundle=Join-Path $Directory 'icannbundle.pem'
if ((Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLower() -ne $ExpectedBundleSha256.ToLower()) { throw 'ICANN CA bundle differs from trusted software pin' }
$certs=[System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$certs.ImportFromPem([IO.File]::ReadAllText($bundle))
$cms=[System.Security.Cryptography.Pkcs.SignedCms]::new([System.Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes((Join-Path $Directory 'root-anchors.xml'))),$true)
$cms.Decode([IO.File]::ReadAllBytes((Join-Path $Directory 'root-anchors.p7s')))
$cms.CheckSignature($certs,$true)
$signers=@()
foreach($signer in $cms.SignerInfos) {
    $chain=[System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.TrustMode=[System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
    $chain.ChainPolicy.RevocationMode=[System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.DisableCertificateDownloads=$true
    $chain.ChainPolicy.ExtraStore.AddRange($certs)
    foreach($cert in $certs) { if($cert.Subject -eq $cert.Issuer) { [void]$chain.ChainPolicy.CustomTrustStore.Add($cert) } }
    if(-not $chain.Build($signer.Certificate)) { throw 'CMS signer does not chain to pinned ICANN CA at current time' }
    $signers+=@{subject=$signer.Certificate.Subject;sha256=$signer.Certificate.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)}
}
if($signers.Count -eq 0) { throw 'No CMS signer' }
@{authentication='CMS_SIGNATURE_AND_PINNED_ICANN_CA_CHAIN';verified_at=[DateTimeOffset]::UtcNow.ToString('o');
  xml_sha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'root-anchors.xml') -Algorithm SHA256).Hash.ToLower();
  bundle_sha256=$ExpectedBundleSha256.ToLower();revocation='not checked offline';signers=$signers} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Receipt -Encoding utf8
