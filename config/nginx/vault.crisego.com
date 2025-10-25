server {
    listen 80;
    server_name vault.crisego.com;

    location / {
        return 301 https://$host$request_uri;
    }
}

limit_req_zone $binary_remote_addr zone=one:10m rate=30r/m;

server {
    listen 443 ssl;
    server_name vault.crisego.com;

    ssl_certificate /etc/ssl/certs/crisego.com.crt;
    ssl_certificate_key /etc/ssl/private/crisego.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    error_page 400 404 500 502 503 504 /error;

    # Permitir que Vaultwarden maneje sus propios errores
    proxy_intercept_errors off;

    # Security headers
    #add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    #add_header X-Content-Type-Options nosniff always;
    #add_header X-Frame-Options DENY always;
    #add_header X-XSS-Protection "0" always;
    #add_header Referrer-Policy "strict-origin-when-cross-origin; same-origin" always;
    #add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self';" always;
    #add_header Feature-Policy "geolocation 'none'; microphone 'none'; camera 'none'" always;
    #add_header X-Robots-Tag "noindex, nofollow, nosnippet, noarchive" always;  # AGREGADO
    #add_header Cross-Origin-Resource-Policy "same-origi  n" always;

    client_max_body_size 128M;

    location / {
        limit_req zone=one burst=5 nodelay;
        proxy_pass http://localhost:8080;  # Puerto expuesto por vaultwarden en docker-compose
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
