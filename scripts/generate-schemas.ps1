Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$schemaDir = Join-Path $root "schemas/json"
$distDir = Join-Path $root "dist"
$summaryPath = Join-Path $distDir "schema-check.json"

New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$expectedSchemas = [ordered]@{
    "delivery_receipt.v2.json" = "iscp.delivery_receipt.v2"
    "device.identity.v2.json" = "iscp.device.identity.v2"
    "device.proof.v2.json" = "iscp.device.proof.v2"
    "error.v2.json" = "iscp.error.v2"
    "pairing_ticket.v2.json" = "iscp.pairing_ticket.v2"
    "provisioning.bundle.v2.json" = "iscp.provisioning.bundle.v2"
    "relay.descriptor.v2.json" = "iscp.relay.descriptor.v2"
    "secure_envelope.v2.json" = "iscp.secure_envelope.v2"
    "session.hello.v2.json" = "iscp.session.hello.v2"
    "session.ready.v2.json" = "iscp.session.ready.v2"
    "signed_descriptor.v2.json" = "iscp.signed_descriptor.v2"
    "trust_grant.v2.json" = "iscp.trust_grant.v2"
    "trust_root.descriptor.v2.json" = "iscp.trust_root.descriptor.v2"
}

$signedSchemas = @{
    "device.proof.v2.json" = $true
    "pairing_ticket.v2.json" = $true
    "provisioning.bundle.v2.json" = $true
    "session.hello.v2.json" = $true
    "session.ready.v2.json" = $true
    "signed_descriptor.v2.json" = $true
    "trust_grant.v2.json" = $true
}

function Get-JsonProperty {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string] $Name
    )

    if ($null -eq $Object -or $null -eq $Object.PSObject) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Has-RequiredField {
    param(
        [Parameter(Mandatory = $true)] $Required,
        [Parameter(Mandatory = $true)] [string] $Name
    )

    return $Name -in @($Required)
}

$errors = @()
$schemaResults = @()
$idSeen = @{}
$typeSeen = @{}

if (!(Test-Path $schemaDir)) {
    $errors += "schemas/json directory is missing"
    $files = @()
} else {
    $files = @(Get-ChildItem -Path $schemaDir -Filter "*.json" | Sort-Object Name)
}

$fileNames = @($files | Select-Object -ExpandProperty Name)
$missingSchemas = @($expectedSchemas.Keys | Where-Object { $_ -notin $fileNames })
$unexpectedSchemas = @($fileNames | Where-Object { $_ -notin $expectedSchemas.Keys })

if ($missingSchemas.Count -gt 0) {
    $errors += "required JSON Schemas are missing: $($missingSchemas -join ', ')"
}
if ($unexpectedSchemas.Count -gt 0) {
    $errors += "schemas/json contains files not in the schema manifest: $($unexpectedSchemas -join ', ')"
}

foreach ($name in $expectedSchemas.Keys) {
    if ($name -in $missingSchemas) {
        continue
    }

    $schemaErrors = @()
    $path = Join-Path $schemaDir $name
    $raw = Get-Content -Raw -Path $path
    try {
        $doc = $raw | ConvertFrom-Json
    } catch {
        $schemaErrors += "invalid JSON: $($_.Exception.Message)"
        $errors += "$name invalid JSON"
        $schemaResults += [ordered]@{ file = $name; object_type = $expectedSchemas[$name]; status = "fail"; errors = $schemaErrors }
        continue
    }

    $schema = Get-JsonProperty $doc '$schema'
    $id = Get-JsonProperty $doc '$id'
    $title = Get-JsonProperty $doc 'title'
    $kind = Get-JsonProperty $doc 'type'
    $additionalProperties = Get-JsonProperty $doc 'additionalProperties'
    $required = @(Get-JsonProperty $doc 'required')
    $properties = Get-JsonProperty $doc 'properties'
    $typeProperty = Get-JsonProperty $properties 'type'
    $typeConst = Get-JsonProperty $typeProperty 'const'
    $expectedType = $expectedSchemas[$name]
    $expectedID = "https://schemas.iscp.dev/json/$name"

    if ($schema -ne "https://json-schema.org/draft/2020-12/schema") {
        $schemaErrors += "must use JSON Schema draft 2020-12"
    }
    if ($id -ne $expectedID) {
        $schemaErrors += "`$id must be $expectedID"
    }
    if ([string]::IsNullOrWhiteSpace($title)) {
        $schemaErrors += "title is required"
    }
    if ($kind -ne "object") {
        $schemaErrors += "top-level type must be object"
    }
    if ($additionalProperties -ne $false) {
        $schemaErrors += "top-level additionalProperties must be false"
    }
    if (!(Has-RequiredField $required "type")) {
        $schemaErrors += "required must include type"
    }
    if ($typeConst -ne $expectedType) {
        $schemaErrors += "properties.type.const must be $expectedType"
    }
    if ($null -ne $id) {
        if ($idSeen.ContainsKey($id)) {
            $schemaErrors += "`$id duplicates $($idSeen[$id])"
        } else {
            $idSeen[$id] = $name
        }
    }
    if ($null -ne $typeConst) {
        if ($typeSeen.ContainsKey($typeConst)) {
            $schemaErrors += "object type duplicates $($typeSeen[$typeConst])"
        } else {
            $typeSeen[$typeConst] = $name
        }
    }

    $signatureProperty = Get-JsonProperty $properties 'signature'
    if ($signedSchemas.ContainsKey($name) -and !(Has-RequiredField $required "signature")) {
        $schemaErrors += "signed schema must require signature"
    }
    if ($signedSchemas.ContainsKey($name) -or $null -ne $signatureProperty) {
        $defs = Get-JsonProperty $doc '$defs'
        $signatureDef = Get-JsonProperty $defs 'signature'
        $signatureRequired = @(Get-JsonProperty $signatureDef 'required')
        $signatureProperties = Get-JsonProperty $signatureDef 'properties'
        $algProperty = Get-JsonProperty $signatureProperties 'alg'
        $valueProperty = Get-JsonProperty $signatureProperties 'value'
        if ($null -eq $signatureDef) {
            $schemaErrors += "signature property must reference a `$defs.signature definition"
        } else {
            foreach ($field in @("alg", "kid", "value")) {
                if (!(Has-RequiredField $signatureRequired $field)) {
                    $schemaErrors += "`$defs.signature.required must include $field"
                }
            }
            if ((Get-JsonProperty $algProperty 'const') -ne "Ed25519") {
                $schemaErrors += "`$defs.signature.properties.alg.const must be Ed25519"
            }
            if ((Get-JsonProperty $valueProperty 'contentEncoding') -ne "base64url") {
                $schemaErrors += "`$defs.signature.properties.value.contentEncoding must be base64url"
            }
        }
    }

    if ($schemaErrors.Count -gt 0) {
        $errors += "$name failed schema validation"
    }

    $schemaResults += [ordered]@{
        file = $name
        id = $id
        object_type = $expectedType
        required_count = $required.Count
        status = $(if ($schemaErrors.Count -eq 0) { "pass" } else { "fail" })
        errors = $schemaErrors
    }
}

$summary = [ordered]@{
    type = "iscp.schema.validation.v2"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    schema_dir = "schemas/json"
    status = $(if ($errors.Count -eq 0) { "pass" } else { "fail" })
    expected_schema_count = $expectedSchemas.Count
    checked_schema_count = $schemaResults.Count
    missing_schemas = $missingSchemas
    unexpected_schemas = $unexpectedSchemas
    schemas = $schemaResults
    errors = $errors
}

$summary | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 -Path $summaryPath

if ($errors.Count -gt 0) {
    throw "JSON Schema validation failed; see dist/schema-check.json"
}

Write-Host "JSON Schema validation passed; see dist/schema-check.json"
