# Use PHP 8.4 CLI Alpine for a lightweight image
FROM php:8.4-cli-alpine

# Install system dependencies
RUN apk add --no-cache \
    sqlite-dev \
    postgresql-dev \
    mysql-dev \
    libcap \
    iptables \
    ip6tables \
    nftables \
    ufw

# Install PHP extensions (SQLite, PostgreSQL, MySQL)
RUN docker-php-ext-install pdo pdo_sqlite pdo_pgsql pdo_mysql

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
RUN mkdir -p logs config data && touch logs/baluarte.log && chmod 666 logs/baluarte.log

# Create non-root user
RUN addgroup -g 1000 baluarte && adduser -u 1000 -G baluarte -D baluarte
RUN chown -R baluarte:baluarte /app

# Switch to non-root user
USER baluarte

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD php baluarte.php status || exit 1

# Set entrypoint
EXPOSE 8080
ENTRYPOINT ["php", "baluarte.php"]
CMD ["scan"]
