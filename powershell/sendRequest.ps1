$body = @{
    username = 'test'
    password = 'test'
}
$headers = @{
    'Content-Type' = 'application/json';
}

$url = 'http://localhost:8080/login'
$method = 'POST'

Invoke-WebRequest -Uri $url -Body $body -Headers $headers -Method $method
