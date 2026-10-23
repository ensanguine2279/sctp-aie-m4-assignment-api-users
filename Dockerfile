# ==========================================
# Stage 1: Build the Application
# ==========================================
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app

# Copy Maven wrapper and POM configuration first (utilizes Docker layer caching for dependencies)
COPY .mvn/ .mvn
COPY mvnw pom.xml ./
RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline -Dexec.skip=true

# Copy source code and build the JAR executable without running unit tests
COPY src ./src
RUN ./mvnw clean package -DskipTests -Dexec.skip=true

# ==========================================
# Stage 2: Runtime Container
# ==========================================
FROM eclipse-temurin:21-jre-alpine

# Install curl (required for the healthcheck command if using Alpine)
RUN apk add --no-cache curl

WORKDIR /app

# Run as a non-root user for security compliance
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copy built JAR artifact from builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose User Service port
EXPOSE 8022

# HEALTHCHECK instruction it tells Docker how to test if a running container is actually 
# functional and ready to handle traffic, rather than just checking if its main process 
# is still alive.
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8022/actuator/health || exit 1

# Configure JVM flags for container resource limits and run
ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]