FROM php:7.4-apache

# Install required extensions and tools
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libldap2-dev \
    sqlite3 \
    libsqlite3-dev \
    && docker-php-ext-install \
    pdo \
    pdo_mysql \
    pdo_sqlite \
    xml \
    ldap

# Enable Apache modules
RUN a2enmod rewrite headers

# Copy application files
COPY ./www/ /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html/
RUN chmod -R 755 /var/www/html/

# Expose port 80
EXPOSE 80

# Start Apache in foreground
CMD ["apache2-foreground"]
