# Define the API endpoint
$apiEndpoint = "https://api.ssllabs.com/api/v2/analyze?host="

# Read domains from a file (one domain per line)
$domains = Get-Content -Path "domains.txt"

# Set the flag to control sending messages to Slack (1 for sending, 0 for not sending)
$sendToSlack = 0

# Set the flag to control displaying progress (1 for showing, 0 for not showing)
$showProgress = 1

# Function to get the SSL Labs report for a domain
function Get-SSLReport($domain) {
    $url = $apiEndpoint + $domain + "&all=done"

    try {
        $response = Invoke-RestMethod -Uri $url
        return $response
    }
    catch [System.Net.WebException] {
        $statusCode = [int]$_.Exception.Response.StatusCode

        switch ($statusCode) {
            400 { Write-Host "Bad request (400) for $domain. Invalid parameters." }
            429 { Write-Host "Client request rate too high (429) for $domain. Try again later." }
            500 { Write-Host "Internal error (500) for $domain." }
            503 { Write-Host "Service is not available (503) for $domain. Service may be down for maintenance." }
            529 { Write-Host "Service is overloaded (529) for $domain." }
            default {
                $retryCount = 10  # Number of retry attempts for API errors
                $retryInterval = 10  # Retry interval in seconds
                $apiErrorMessage = "API error ($statusCode) for $domain."

                while ($retryCount -ge 0) {
                    Write-Host "$apiErrorMessage Retrying in $retryInterval seconds (Retry Count: $($retryCount + 1))..."
                    Send-SlackNotification "$apiErrorMessage Retrying (Retry Count: $($retryCount + 1))..."
                    Start-Sleep -Seconds $retryInterval
                    $retryCount--
                }

                Write-Host "$apiErrorMessage Maximum retry count reached. Skipping."
                Send-SlackNotification "$apiErrorMessage Maximum retry count reached. Skipping."

                return $null
            }
        }
    }
}

# Function to check the SSL Labs report progress for a domain
function Check-Progress($domain) {
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Host "Empty or unspecified domain. Skipping."
        return
    }

    $retryCount = 10  # Number of retry attempts for empty domain
    $retryInterval = 10  # Retry interval in seconds
    $percentWait = 10
    $retryInProgress = $false

    # Display scanning start message in Slack and on the screen
    Send-SlackNotification "Scanning $domain starting..."
    Write-Host "Scanning $domain..."

    while ($retryCount -ge 0) {
        $report = Get-SSLReport $domain

        if ($report -eq $null) {
            Start-Sleep -Seconds $retryInterval
            $retryCount--
        }
        else {
            if ($report.endpoints -eq $null -or $report.endpoints.Count -eq 0) {
                $errorMessage = "No cache detected for $domain"
                Write-Host $errorMessage
                Send-SlackNotification $errorMessage
                Start-Sleep -Seconds $retryInterval
                $retryCount--
            }
            else {
                $progress = $report.endpoints[0].progress
                $statusDetailsMessage = $report.endpoints[0].statusDetailsMessage
                $status = $report.status

                # Send progress to Slack and on the screen if $showProgress is 1
                if ($showProgress -eq 1) {
                    Send-SlackNotification "Progress for $domain : $progress% : $statusDetailsMessage" -nopretext $true
                    Write-Host "Progress for $domain : $progress% : $statusDetailsMessage"
                }

                if ($status -eq "READY") {
                    $grade = $report.endpoints[0].grade
                    $ipAddress = $report.endpoints[0].ipAddress
                    $cert = $report.endpoints[0].details.cert.subject

                    # Define ANSI escape codes for red color (Windows Console supports this)
                    $redColor = [char]27 + '[91m'
                    $resetColor = [char]27 + '[0m'

                    # Print the grade in red
                    Write-Host "Grade for $domain : ${redColor}$grade${resetColor} - $ipAddress  - $cert"

                    # Send a Slack message for the result of each domain if $sendToSlack is 1
                    if ($sendToSlack -eq 1) {
                        Send-SlackNotification "Grade for $domain : $grade - $ipAddress  - $cert" -color "#AF0000" -nopretext $true -attachments $true
                    }

                    return
                }

                if ($retryCount -gt 0) {
                    # Retry the scan
                    if (!$retryInProgress) {
                        $retryInProgress = $true
                        Send-SlackNotification "Retrying scan for $domain (Retry Count: $retryCount)..."
                        Write-Host "Retrying scan for $domain (Retry Count: $retryCount)..."
                    }
                }
            }
        }

        Start-Sleep -Seconds $percentWait
    }

    # If all retry attempts failed, send a final error message to Slack and on the screen
    $finalErrorMessage = "Maximum retry count reached for $domain. Skipping."
    Write-Host $finalErrorMessage
    Send-SlackNotification $finalErrorMessage -nopretext $true
}

# Function to send a notification to Slack with custom color
function Send-SlackNotification($message, $color = "#FF0000", $nopretext = $false, $attachments = $false) {
    if ($sendToSlack -eq 0) {
        Write-Host "Not sending message to Slack: $message"
        return
    }

    $uriSlack = "https://hooks.slack.com/..."
    $url = "https://www.ssllabs.com/ssltest/analyze.html?d=$domain&hideResults=on"

    $bodyParams = @{
        text = $message
        color = $color  # Set the color to red (#AF0000)
    }

    if ($attachments) {
        $attachment = @{
            fallback = "SSL Labs Analysis"
            title = "SSL Labs Analysis"
            title_link = $url
        }
        $bodyParams.Add("attachments", @($attachment))
    }

    if (-not $nopretext) {
        $bodyParams.Add("pretext", "")
    }

    $body = ConvertTo-Json $bodyParams

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-RestMethod -Uri $uriSlack -Method Post -body $body -ContentType 'application/json' | Out-Null
    } catch {
        Write-Error (Get-Date) ": Update to Slack went wrong..."
    }
}

# Send the title message only once
Send-SlackNotification "initial_slack_message"

# Iterate through the domains and perform SSL Labs scans
foreach ($domain in $domains) {
    Check-Progress $domain
}

Write-Host "SSL Labs scans completed for all domains."
