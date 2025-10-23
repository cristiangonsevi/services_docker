# --- tunnel.crisego.com -> redirige a qa.taakmx.com ---
#server {
#    listen 80;
#    server_name tunnel.crisego.com;
#
#    return 301 https://qa.taakmx.com$request_uri;
#}
#
#server {
#    listen 443 ssl;
#    server_name tunnel.crisego.com;
#
#    ssl_certificate /etc/ssl/certs/crisego.com.crt;
#    ssl_certificate_key /etc/ssl/private/crisego.com.key;
#
#    return 301 https://qa.taakmx.com$request_uri;
#}


 server {
        listen 80;
        server_name *.crisego.com; # Escucha para ambos

        # Redirigir todo HTTP a HTTPS
        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        server_name *.crisego.com; # Escucha para ambos

        # Rutas a tus certificados SSL (reemplaza con tus rutas reales)
        ssl_certificate /etc/ssl/certs/crisego.com.crt;
        ssl_certificate_key /etc/ssl/private/crisego.com.key;


        # Configuraciones SSL recomendadas
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers off;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

        access_log /var/log/nginx/frp-proxy.access.log;
        error_log /var/log/nginx/frp-proxy.error.log;

        location / {
            proxy_pass http://127.0.0.1:7080; # Pasa al vhostHTTPPort de frps [cite: 17]
            proxy_set_header Host $host; # Esencial para que frps sepa qué dominio/subdominio es
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
