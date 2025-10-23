server {
    listen 80;
    server_name duplicati.crisego.com;

    location / {
        proxy_pass http://localhost:8200;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Redirección a HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name duplicati.crisego.com;

    ssl_certificate /etc/ssl/certs/crisego.com.crt;
    ssl_certificate_key /etc/ssl/private/crisego.com.key;

    location / {
        proxy_pass http://localhost:8200;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
