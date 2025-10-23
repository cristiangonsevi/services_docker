server {
    listen 80;
    server_name status.crisego.com;

    # Redirección de HTTP a HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name status.crisego.com;

    # Ruta a los certificados SSL
    ssl_certificate /etc/ssl/certs/crisego.com.crt;
    ssl_certificate_key /etc/ssl/private/crisego.com.key;


    location / {
        proxy_pass http://localhost:3001;  # Puerto expuesto por uptimekuma en docker-compose
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
