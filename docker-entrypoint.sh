#!/bin/bash

echo "Starten van IP Manager..."

# Start Nginx in de achtergrond
echo "Start Nginx..."
service nginx start

# Start de Node.js backend (dit blijft draaien op de voorgrond)
echo "Start Node.js Backend..."
exec node server.js
