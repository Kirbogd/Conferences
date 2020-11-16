<##

First iteration of code snippets for Standoff365 talk on Microsoft cloud services audit

Just follow the code and set your-tenant specific settings

Work to do:

turn JWT token creation regions into function. 

pretify output

##>


#region Certificate creation

    $Appcert = New-SelfSignedCertificate -Subject "CN=LogCheckService" -CertStoreLocation "Cert:\CurrentUser\My" -KeySpec Signature -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -HashAlgorithm "SHA256"  

    Write-Host $Appcert

    Export-Certificate -Cert $Appcert -Type CERT -FilePath C:\Distr\AppCert.cer

#endregion

# Azure Log Analytics Query

#region Phase0: initialize settings

    $clientID = "????????-????-????-????-????????????" ## Found in app settings for your app principle 

    $TenantName = "????.onmicrosoft.com" ## Your tenant name
    
    $audience = "https://login.microsoftonline.com/$TenantName/oauth2/token"  ##Audience settings for token 

    $RedirectURI = "logcheck://auth" ## Provided on the app registration phase. change if you set your own Redirect URI there

    $TenantID = "????????-????-????-????-????????????" ## Found on overview tab of your app registration

    $WorkSpaceID = "????????-????-????-????-????????????" ## found on overview tab of your Azure Log Analytics Workspace

    $Resource = "https://api.loganalytics.io" 

    $Query = "IntuneAuditLogs"  ## insert your KQL Query here

    $TimeSpan = "PT24H" ## insert your value for time period in ISO8601 format https://en.wikipedia.org/wiki/ISO_8601

#endregion

#region Phase1 Create JWT assertion 

    # The code inspired by https://adamtheautomator.com/microsoft-graph-api-powershell/#Acquire_an_Access_Token_(Using_a_Certificate)

    # Get base64 hash of certificate
    
    $CertBase64Hash = [System.Convert]::ToBase64String($Appcert.GetCertHash())

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

    $JWTPayLoad = @{
    
    # What endpoint is allowed to use this JWT
    aud = $audience

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
    $PrivateKey = $Appcert.PrivateKey

    # Define RSA signature and hashing algorithm
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1

    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

    # Create a signature of the JWT
    $Signature = [Convert]::ToBase64String($PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)) -replace '\+','-' -replace '/','_' -replace '='

    # Join the signature to the JWT with "."
    $JWT = $JWT + "." + $Signature
          
    $AuthUri = $audience

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

    $AuthRequest = Invoke-RestMethod -Uri $AuthUri -Method Post -Headers $authReqHeader -Body $AuthReqBody -ContentType 'application/x-www-form-urlencoded'

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

    ## Form header for REST request. It should contain auth bearer ackquired on the rpevios phase
    $QueryHeader = @{
                'Content-Type'='application/json';
                'Authorization' = "Bearer " + $AuthRequest.access_token;
                'ExpiresOn'=$authRequest.Expires_On;
                }
    ## Invoking REST request to API. The quiry result should be returned in responce            
    $Result = Invoke-RestMethod -Uri $QueryURi -Method Post -Headers $QueryHeader -Body $LogQuery
    
    ## Writing our result: table with columns and rows in JSON format
    $Result

#endregion 

# Graph API (sign-ins)

#region Phase0: initialize settings

    $clientID = "????????-????-????-????-????????????" ## Found in app settings for your app principle 

    $TenantName = "????.onmicrosoft.com" ## Your tenant name
    
    $audience = "https://login.microsoftonline.com/$TenantName/oauth2/token"  ##Audience settings for token 
    
    ## $ClientKey = ## Generate in Certificates and secrets settings of the app principle

    $RedirectURI = "logcheck://auth" ## Provided on the app registration phase. change if you set your own Redirect URI there

    $TenantID = "????????-????-????-????-????????????" ## Found on overview tab of your app registration

    $Resource = "https://graph.microsoft.com" 

    
#endregion

#region Phase1 Create JWT assertion 

    # The code inspired by https://adamtheautomator.com/microsoft-graph-api-powershell/#Acquire_an_Access_Token_(Using_a_Certificate)

    # Get base64 hash of certificate
    
    $CertBase64Hash = [System.Convert]::ToBase64String($Appcert.GetCertHash())

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

    $JWTPayLoad = @{
    
    # What endpoint is allowed to use this JWT
    aud = $audience

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
    $PrivateKey = $Appcert.PrivateKey

    # Define RSA signature and hashing algorithm
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1

    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

    # Create a signature of the JWT
    $Signature = [Convert]::ToBase64String($PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)) -replace '\+','-' -replace '/','_' -replace '='

    # Join the signature to the JWT with "."
    $JWT = $JWT + "." + $Signature
          
    $AuthUri = $audience

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

    $AuthRequest = Invoke-RestMethod -Uri $AuthUri -Method Post -Headers $authReqHeader -Body $AuthReqBody -ContentType 'application/x-www-form-urlencoded'

#endregion

#region Phase2:quering Graph API for Sign-ins

    ## Setting URI for quiring Log Analytics API for specific workspace
    
    $BaseURI = "https://graph.microsoft.com/beta"

    $SubURI = "auditlogs/signins"
    
    $QueryURi = "$BaseURI/$SubURI"

    ## Form header for REST request. It should contain auth bearer ackquired on the rpevios phase
    $QueryHeader = @{
                'Content-Type'='application/json';
                'Authorization' = "Bearer " + $AuthRequest.access_token;
                'ExpiresOn'=$authRequest.Expires_On;
                }
    ## Invoking REST request to API. The quiry result should be returned in responce            
    $Result = Invoke-RestMethod -Uri $QueryURi -Method Get -Headers $QueryHeader 
    
    ## Writing our result: table with columns and rows in JSON format
    $Result

#endregion 

# Office 365 Activity API

#region Phase0: initialize settings

    $clientID = "????????-????-????-????-????????????" ## Found in app settings for your app principle 

    $TenantName = "????.onmicrosoft.com" ## Your tenant name
    
    $RedirectURI = "logcheck://auth" ## Provided on the app registration phase. change if you set your own Redirect URI there

    $TenantID = "????????-????-????-????-????????????" ## Found on overview tab of your app registration

    $Resource = "https://manage.office.com" 

    $audience = "https://login.windows.net/$TenantName/oauth2/token"

    
#endregion

#region Phase1 Create JWT assertion 

    # The code inspired by https://adamtheautomator.com/microsoft-graph-api-powershell/#Acquire_an_Access_Token_(Using_a_Certificate)

    # Get base64 hash of certificate
    
    $CertBase64Hash = [System.Convert]::ToBase64String($Appcert.GetCertHash())

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

    $JWTPayLoad = @{
    
    # What endpoint is allowed to use this JWT
    aud = $audience

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
    $PrivateKey = $Appcert.PrivateKey

    # Define RSA signature and hashing algorithm
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1

    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

    # Create a signature of the JWT
    $Signature = [Convert]::ToBase64String($PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)) -replace '\+','-' -replace '/','_' -replace '='

    # Join the signature to the JWT with "."
    $JWT = $JWT + "." + $Signature
          
    $AuthUri = $audience

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

    $AuthRequest = Invoke-RestMethod -Uri $AuthUri -Method Post -Headers $authReqHeader -Body $AuthReqBody -ContentType 'application/x-www-form-urlencoded'

#endregion

#region Phase2:quering Graph API for Sign-ins

    ## Setting URI for quiring Log Analytics API for specific workspace
    
    $BaseURI = "https://manage.office.com/api/v1.0/$TenantID/activity/feed"

    $SubURI = "subscriptions/list"
    
    $QueryURi = "$BaseURI/$SubURI"

    ## Form header for REST request. It should contain auth bearer ackquired on the rpevios phase
    $QueryHeader = @{
                'Content-Type'='application/json';
                'Authorization' = "Bearer " + $AuthRequest.access_token;
                'ExpiresOn'=$authRequest.Expires_On;
                }
    ## Invoking REST request to API. The quiry result should be returned in responce            
    $Result = Invoke-RestMethod -Uri $QueryURi -Method Get -Headers $QueryHeader 
    
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
     
        $SubURI = "/subscriptions/start?contentType="+$_
    
        $QueryURi = "$BaseURI/$SubURI"

        ## Form header for REST request. It should contain auth bearer ackquired on the rpevios phase
        $QueryHeader = @{
                
                'Content-Type'='application/json';
                
                'Authorization' = "Bearer " + $AuthRequest.access_token;
                
                'ExpiresOn'=$authRequest.Expires_On;
                }

        ## Invoking REST request to API. The quiry result should be returned in responce            
        $Result = Invoke-RestMethod -Uri $QueryURi -Method post -Headers $QueryHeader 
        
        write-host $Result

    }
    
    ## Checking content

    ## Getting content URIs
     
     $Buckets = @()


    $SubType | ForEach-Object {
     
        $SubURI = "/subscriptions/content?contentType="+$_
    
        $QueryURi = "$BaseURI/$SubURI"

        ## Form header for REST request. It should contain auth bearer ackquired on the rpevios phase
        $QueryHeader = @{
                
                'Content-Type'='application/json';
                
                'Authorization' = "Bearer " + $AuthRequest.access_token;
                
                'ExpiresOn'=$authRequest.Expires_On;
                }

        ## Invoking REST request to API. The quiry result should be returned in responce            
        $Result = Invoke-RestMethod -Uri $QueryURi -Method get -Headers $QueryHeader 
        
        write-host $Result

        $Buckets = $Buckets + $Result

    }

    ## Retrieve events

    $Events = @()

    $Buckets | ForEach-Object {
    
        $QueryURi = $_.contentUri

         ## Form header for REST request. It should contain auth bearer ackquired on the rpevios phase
        $QueryHeader = @{
                
                'Content-Type'='application/json';
                
                'Authorization' = "Bearer " + $AuthRequest.access_token;
                
                'ExpiresOn'=$authRequest.Expires_On;
                }

        ## Invoking REST request to API. The quiry result should be returned in responce            
        $Result = Invoke-RestMethod -Uri $QueryURi -Method get -Headers $QueryHeader

        $Events = $Events + $Result
    }

    
#endregion 