# A short-lived HTTP fixture with two routes, accessible only inside the guest.
$ErrorActionPreference = 'Stop'
$root = 'C:\Week8Lab'
$log = Join-Path $root 'http.jsonl'
$base = 'http://127.0.0.1:18768/'
$server = New-Object Net.HttpListener
$server.Prefixes.Add($base)
$server.Start()
try {
    [IO.File]::WriteAllText("$root\ready.txt", "$PID")
    while ($server.IsListening) {
        $context = $server.GetContext()
        $request = $context.Request
        $response = $context.Response
        $path = $request.Url.AbsolutePath
        $code = 404
        $received = 0
        $digest = $null
        $body = [byte[]]@()
        if ($request.HttpMethod -eq 'GET' -and $path -eq '/update') {
            $body = [IO.File]::ReadAllBytes("$root\update.html")
            $response.ContentType = 'text/html; charset=utf-8'
            $code = 200
        } elseif ($request.HttpMethod -eq 'POST' -and $path -eq '/receive' -and
                  $request.ContentLength64 -gt 0 -and $request.ContentLength64 -le 1048576) {
            $stream = [IO.File]::Open("$root\received.zip", 'CreateNew', 'Write', 'None')
            try { $request.InputStream.CopyTo($stream); $received = $stream.Length } finally { $stream.Dispose() }
            $digest = (Get-FileHash "$root\received.zip").Hash
            if ($received -ne $request.ContentLength64) { throw 'Incomplete HTTP request body' }
            $code = 201
        }
        $response.StatusCode = $code
        $response.ContentLength64 = $body.Length
        $entry = [ordered]@{utc=[datetime]::UtcNow.ToString('o');method=$request.HttpMethod;path=$path;
            remote=$request.RemoteEndPoint.Address.ToString();local=$request.LocalEndPoint.Address.ToString();
            port=$request.LocalEndPoint.Port;status=$code;bytes_saved=$received;sha256=$digest}
        [IO.File]::AppendAllText($log, (($entry | ConvertTo-Json -Compress) + [Environment]::NewLine))
        if ($body.Length) { $response.OutputStream.Write($body,0,$body.Length) }
        $response.Close()
        if ($code -eq 201) { break }
    }
} finally { $server.Close() }
