# Stap 1: Gebruik een Node.js image die gebaseerd is op Debian (stabiel voor netwerk tools)
FROM node:18-bullseye-slim

# Stap 2: Installeer Nginx en netwerk tools (nodig voor de scan)
# net-tools bevat 'arp', iputils-ping bevat 'ping'
RUN apt-get update && apt-get install -y \
    nginx \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Stap 3: Werkmap instellen voor de backend
WORKDIR /app

# Stap 4: Backend afhankelijkheden installeren
# We kopiëren eerst alleen package bestanden voor betere caching
COPY package.json ./
RUN npm install

# Stap 5: Backend code kopiëren
COPY server.js ./

# Stap 6: Frontend code kopiëren naar de Nginx map
# Zorg dat je index.html in dezelfde map staat als deze Dockerfile
COPY index.html /var/www/html/index.html

# Stap 7: Nginx configuratie toevoegen
COPY nginx.conf /etc/nginx/sites-available/default

# Stap 8: Start script toevoegen
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Stap 9: Poort 80 openzetten (Nginx)
EXPOSE 80

# Stap 10: Start alles via het script
ENTRYPOINT ["docker-entrypoint.sh"]
