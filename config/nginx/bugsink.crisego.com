server {
    listen 80;
    server_name bugsink.crisego.com;

    # Redirección de HTTP a HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name bugsink.crisego.com;

    # Ruta a los certificados SSL
    ssl_certificate /etc/ssl/cer/crisego.com.crt;
    ssl_certificate_key /etc/ssl/private/crisego.com.key;


    location / {
        proxy_pass http://localhost:8100;  # Redirige el tráfico al puerto 9090
	proxy_http_version 1.1;
    	proxy_set_header Upgrade $http_upgrade;
    	proxy_set_header Connection 'upgrade';
    	proxy_set_header Host $host;
    	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    	proxy_set_header X-Forwarded-Proto $scheme;
    	proxy_set_header X-Forwarded-Host $host;
    	proxy_set_header X-Forwarded-Port $server_port;
    	proxy_cache_bypass $http_upgrade;
    }
}
