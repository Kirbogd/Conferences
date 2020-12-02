<##

Refactored code snippets for Standoff365 talk on Microsoft cloud services audit

Just follow the code and set your-tenant specific settings

Load specific settings are located in the corressponding regions after function declaration

Changes: 
    Turned getting auth header into function
    Added function to get header using clientsecret
    Tested code for functions, graph and management APIs

Work to do:

Test LogAnalytics query 

##>

#region Certificate creation

   <#  # create self-signed certificate in currentuser personal certificates 
    # Attention!!!: Hash algorithm has to be SHA256 or it can't be used to sign JWT assertion
    $GeneratedCert = New-SelfSignedCertificate -Subject "CN=LogCheckService" -CertStoreLocation "Cert:\CurrentUser\My" -KeySpec Signature -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -HashAlgorithm "SHA256"  

    Write-Host $GeneratedCert

    # Export certificate to upload into application settings
    Export-Certificate -Cert $GeneratedCert -Type CERT -FilePath C:\Distr\AppCert.cer
 #>
#endregion


#region Phase0: initialize common settings 

$clientID = "????????-????-????-????-????????????" ## Found in app settings for your app principle 

$TenantName = "????.onmicrosoft.com" ## Your tenant name

$TenantID = "????????-????-????-????-????????????" ## Found on overview tab of your app registration

$Redirect = "logcheck://auth" ## Provided on the app registration phase. change if you set your own Redirect URI there

$authenticatorType = "0" #set 0 for certificate or 1 for secretkey  

$SecretKey = ""  #set key in case of using it instead of a certificate

$Appcert = $GeneratedCert # change for thumbprint or certificate object (get-item cert:\my\...) in case cert creation is done previously

#endregion

#region functions

function New-CertBasedAuthHeader {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $CertInput,
        [uri]$Audience,
        [ValidatePattern('([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})')]
        [string]$ClientID,
        [string]$RedirectURI,
        [uri]$Resource
    )
    
    #Check $CertInput type and get certificate object in case of string

    write-host $CertInput.GetType().FullName 
    if ($CertInput.getType().FullName -ne "System.Security.Cryptography.X509Certificates.X509Certificate2")
        {
     
        write-host "Not a cert, trying to find object"
 
        $Certificate = (Get-ChildItem -Path "cert:\*\My" -Recurse | where {$_.Thumbprint -eq $CertInput})
     
        if ($null -eq $Certificate)
            {
            write-error "The cert is not thumbprint, nor cert object "
           
            break                
            }    
        }
 
        else
            {
     
            Write-host "Certificate"
 
            $Certificate = $CertInput
 
            }
 
    # The code is inspired by https://adamtheautomator.com/microsoft-graph-api-powershell/#Acquire_an_Access_Token_(Using_a_Certificate)

    # Get base64 hash of certificate
    
    $CertBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

    # JWT timestamp for expiration
    
    $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()

    $JWTExpTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(3)).TotalSeconds

    $JWTExp = [math]::Round($JWTExpTimeSpan,0)

    # Create JWT timestamp for validity start

    $NotBeforeExpTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    
    $NotBefore = [math]::Round($NotBeforeExpTimeSpan,0)

    # Create JWT header
    
    $JWTHeader = @{
    
        alg = "RS256"
    
        typ = "JWT"
    
        # Use the CertBase64Hash replacing/striping to match web encoding of base64
    
        x5t = $CertBase64Hash -replace '\+','-' -replace '/','_' -replace '='
    }

    # Create JWT payload

    $aud = $Audience.OriginalString

    $JWTPayLoad = @{
    
        # What endpoint is allowed to use this JWT
        aud = $aud

        # Expiration timestamp
        exp = $JWTExp

        # Issuer = your application
        iss = $clientID

        # JWT ID: random guid
        jti = [guid]::NewGuid()

        # Not to be used before
        nbf = $NotBefore

        # JWT Subject
        sub = $clientID
        }
        
         # Convert header and payload to base64

    $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))

    $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

    $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
    
    $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

    # Join header and Payload with "." to create a valid (unsigned) JWT
    $JWT = $EncodedHeader + "." + $EncodedPayload

    # Get the private key object of your certificate
    $PrivateKey = $Certificate.PrivateKey

    # Define RSA signature and hashing algorithm
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1

    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

    # Create a signature of the JWT
    $Signature = [Convert]::ToBase64String($PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)) -replace '\+','-' -replace '/','_' -replace '='

    # Join the signature to the JWT with "."
    $JWT = $JWT + "." + $Signature
          
    # Use the self-generated JWT as Authorization

    $AuthReqHeader = @{
        
        Authorization = "Bearer $JWT"
    
        }

    # Create a hash with body parameters

    $AuthReqBody = @{
    
        grant_type = "client_credentials"
    
        client_id = $clientID
    
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    
        redirect_uri = $RedirectURI
    
        resource = $Resource
    
        client_assertion = $JWT
    
        }    
        
        # Setting parameters for request
        $SplatHash = @{
            Uri = $Audience
            Method = 'POST'
            Headers = $authReqHeader
            Body = $AuthReqBody
            ContentType = 'application/x-www-form-urlencoded'
        } 

        $AuthRequest = Invoke-RestMethod @SplatHash
    
        $QueryHeader = @{
            'Content-Type'='application/json';
            'Authorization' = "Bearer " + $AuthRequest.access_token;
            'ExpiresOn'=$authRequest.Expires_On;
            } 

        return $QueryHeader
    }

function New-KeyBasedAuthHeader {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Secret,
        [uri]$Audience,
        [ValidatePattern('([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})')]
        [string]$ClientID,
        [uri]$RedirectURI,
        [uri]$Resource
    )
    
    # Set web request header for auth token request
    $authReqHeader = @{
        'Content-Type'='application/x-www-form-urlencoded'
        }
    
    ##  The auth request body contains data required to authenticate client  
    $AuthReqBody = "grant_type=client_credentials&client_id=$clientID&redirect_uri=$RedirectURI&resource=$Resource&client_secret=$Secret"
        
    $SplatHash = @{
        Uri = $Audience
        Method = 'POST'
        Headers = $authReqHeader
        Body = $AuthReqBody
        }

    ## Issuing web request to get bearer. It is returned in responce to web request
    $AuthRequest = Invoke-WebRequest @SplatHash

    #Getting AuthBearer from authentication response
    $AuthBearer = ($AuthRequest.Content | ConvertFrom-Json)

    ## Form header for REST request. It should contain auth bearer ackquired on the rpevios phase
    $QueryHeader = @{
        
        'Content-Type'='application/json';
        
        'Authorization' = "Bearer " + $AuthBearer.access_token;
        
        'ExpiresOn'=$authBearer.Expires_On;
        
    }

    return $QueryHeader

}

#endregion


#region Azure Log Analytics Query

    $audience = "https://login.microsoftonline.com/$TenantName/oauth2/token"  ##Audience settings for token 

    $WorkSpaceID = "????????-????-????-????-????????????" ## found on overview tab of your Azure Log Analytics Workspace

    $Resource = "https://api.loganalytics.io" 

    $Query = "IntuneAuditLogs"  ## insert your KQL Query here

    $TimeSpan = "PT24H" ## insert your value for time period in ISO8601 format https://en.wikipedia.org/wiki/ISO_8601

#region Phase1 Getting auth header

    if ('0' -eq $authenticatorType){
        # auth type set to certificate. Use New-CertBasedAuthHeader

        $SplatHash = @{
            CertInput = $Appcert
            Audience = $audience
            ClientID = $clientID
            RedirectURI = $Redirect
            Resource = $Resource    
        }

        $AuthHeader = New-CertBasedAuthHeader @SplatHash

    }
    elseif ('1' -eq $authenticatorType) {
        # auth type set to certificate. Use New-KeyBasedAuthHeader
        
        $SplatHash = @{
            Secret = $SecretKey
            Audience = $audience
            ClientID = $clientID
            RedirectURI = $Redirect
            Resource = $Resource    
        }

        $AuthHeader = New-KeyBasedAuthHeader @SplatHash
    }
    else {
        # AuthType set is not valid
        Write-Error "AuthType is not set or invalid. Check declaration part"

        break
    }
#endregion

#region Phase2:quering AzureLogAnalytics API for data

    ## From request body consisting of KQL query and timespan for requested data
    ## The body should be formatred as JSON object
    $LogQuery = @{
    'query'= $Query;
    'timespan'= $TimeSpan
    } | ConvertTo-Json

    ## Setting URI for quiring Log Analytics API for specific workspace
    $QueryURi = "https://api.loganalytics.io/v1/workspaces/$WorkSpaceID/query"
    
    ## Invoking REST request to API. The quiry result should be returned in responce            
    
    $Uri = [uri]::new($QueryUri)

    $SplatHash = @{
        Uri = $Uri
        Method = 'POST' 
        Headers = $AuthHeader 
        Body = $LogQuery
    }
    
    $Result = Invoke-RestMethod @SplatHash
    
    ## Writing our result: table with columns and rows in JSON format
    $Result

#endregion 

# Graph API (sign-ins)

#region Phase0: initialize settings

    $audience = "https://login.microsoftonline.com/$TenantName/oauth2/token"  ##Audience settings for token 
    
    $Resource = "https://graph.microsoft.com" 
    
#endregion

#region Phase1 Getting auth header

    if ('0' -eq $authenticatorType){
        # auth type set to certificate. Use New-CertBasedAuthHeader

        $SplatHash = @{
            CertInput = $Appcert
            Audience = $audience
            ClientID = $clientID
            RedirectURI = $Redirect
            Resource = $Resource    
        }

        $AuthHeader = New-CertBasedAuthHeader @SplatHash

    }
    elseif ('1' -eq $authenticatorType) {
        # auth type set to certificate. Use New-KeyBasedAuthHeader
        
        $SplatHash = @{
            Secret = $SecretKey
            Audience = $audience
            ClientID = $clientID
            RedirectURI = $Redirect
            Resource = $Resource    
        }

        $AuthHeader = New-KeyBasedAuthHeader @SplatHash
    }
    else {
        # AuthType set is not valid
        Write-Error "AuthType is not set or invalid. Check declaration part"

        break
    }
#endregion

#region Phase2:quering Graph API for Sign-ins

    ## Setting URI for quiring Log Analytics API for specific workspace
    
    $BaseURI = "https://graph.microsoft.com/beta"

    $SubURI = "auditlogs/signins"
    
    $QueryURi = "$BaseURI/$SubURI"

    ## Invoking REST request to API. The quiry result should be returned in responce            
    
    $Uri = [uri]::new($QueryUri)

    $SplatHash = @{
        Uri = $Uri
        Method = 'GET'
        Headers = $AuthHeader 
    }
    
    $Result = Invoke-RestMethod @SplatHash 
    
    ## Writing our result: table with columns and rows in JSON format
    $Result

#endregion 

# Office 365 Activity API

#region Phase0: initialize settings

    $audience = "https://login.windows.net/$TenantName/oauth2/token"

    $Resource = "https://manage.office.com" 
    
#endregion

#region Phase1 Getting auth header

    if ('0' -eq $authenticatorType){
        # auth type set to certificate. Use New-CertBasedAuthHeader

        $SplatHash = @{
            CertInput = $Appcert
            Audience = $audience
            ClientID = $clientID
            RedirectURI = $Redirect
            Resource = $Resource    
        }

        $AuthHeader = New-CertBasedAuthHeader @SplatHash

    }
    elseif ('1' -eq $authenticatorType) {
        # auth type set to certificate. Use New-KeyBasedAuthHeader
        
        

        $SplatHash = @{
            Secret = $SecretKey
            Audience = $audience
            ClientID = $clientID
            RedirectURI = $Redirect
            Resource = $Resource    
        }

        $AuthHeader = New-KeyBasedAuthHeader @SplatHash
    }
    else {
        # AuthType set is not valid
        Write-Error "AuthType is not set or invalid. Check declaration part"

        break
    }
#endregion

#region Phase2:quering Graph API for Sign-ins

    ## Setting URI for quiring Log Analytics API for specific workspace
    
    $BaseURI = "https://manage.office.com/api/v1.0/$TenantID/activity/feed"

    $SubURI = "subscriptions/list"
    
    $QueryURi = "$BaseURI/$SubURI"

    $Uri = [uri]::new($QueryUri)

    ## Invoking REST request to API. The quiry result should be returned in responce            
    $SplatHash = @{
        Uri = $Uri
        Method = 'GET' 
        Headers = $AuthHeader
    }

    $Result = Invoke-RestMethod @SplatHash  
    
    ## Writing our result: table with columns and rows in JSON format
    $Result

    ##Enable subscriptions

    $SubType = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
    "DLP.All"
    )
    
    $Events = @()


    $SubType | ForEach-Object {
     
        
        if(($Result -match $_).status -eq "enabled"){
            Write-host "$_ content is already enabled"
        }
        else {
            $SubURI = "/subscriptions/start?contentType="+$_
        
            $QueryURi = "$BaseURI/$SubURI"

            ## Invoking REST request to API. The quiry result should be returned in responce            
            $SplatHash = @{
                Uri = $QueryURi
                Method = 'POST' 
                Headers = $AuthHeader
            }

            $Result = Invoke-RestMethod @SplatHash  
            
            write-host $Result
        }
    }
    
    ## Checking content

    ## Getting content URIs
     
     $Buckets = @()


    $SubType | ForEach-Object {
     
        $SubURI = "/subscriptions/content?contentType="+$_
    
        $QueryURi = "$BaseURI/$SubURI"

         ## Invoking REST request to API. The quiry result should be returned in responce            
        $SplatHash = @{
            Uri = $QueryURi
            Method = 'GET' 
            Headers = $AuthHeader
        }

        $Result = Invoke-RestMethod @SplatHash   
        
        write-host $Result

        $Buckets = $Buckets + $Result

    }

    ## Retrieve events

    $Events = @()

    $Buckets | ForEach-Object {
    
        $QueryURi = $_.contentUri

         ## Invoking REST request to API. The quiry result should be returned in responce            
        $SplatHash = @{
            Uri = $QueryURi
            Method = 'GET' 
            Headers = $AuthHeader
        }

    $Result = Invoke-RestMethod @SplatHash  
        $Events = $Events + $Result
    }

    
#endregion 