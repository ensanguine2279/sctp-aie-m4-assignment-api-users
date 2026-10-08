# ==========================================
# Stage 1: Build the Application
# ==========================================
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app

# Copy Maven wrapper and POM configuration first (utilizes Docker layer caching for dependencies)
COPY .mvn/ .mvn
COPY mvnw pom.xml ./
RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline

# Copy source code and build the JAR executable without running unit tests
COPY src ./src
RUN ./mvnw clean package -DskipTests

# ==========================================
# Stage 2: Runtime Container
# ==========================================
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Run as a non-root user for security compliance
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copy built JAR artifact from builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose User Service port
EXPOSE 8080

# Configure JVM flags for container resource limits and run
ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]