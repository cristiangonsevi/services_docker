server {
    listen 80;
    server_name mailpit.crisego.com;

    # Redirección de HTTP a HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name mailpit.crisego.com;

    # Ruta a los certificados SSL
    ssl_certificate /etc/ssl/certs/crisego.com.crt;
    ssl_certificate_key /etc/ssl/private/crisego.com.key;

    location / {
        proxy_pass http://localhost:8025;  # Puerto web UI de Mailpit
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
