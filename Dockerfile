# Use PHP 8.4 CLI Alpine for a lightweight image
FROM php:8.4-cli-alpine

# Install system dependencies
RUN apk add --no-cache \
    sqlite-dev \
    libcap \
    iptables \
    ip6tables \
    nftables \
    ufw

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_sqlite

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /app

# Copy composer files and install dependencies
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader

# Copy the rest of the application
COPY . .

# Create directories and log file, and set permissions
RUN mkdir -p logs config && touch logs/baluarte.log && chmod 666 logs/baluarte.log

# Set entrypoint
EXPOSE 8080
ENTRYPOINT ["php", "baluarte.php"]
CMD ["scan"]
