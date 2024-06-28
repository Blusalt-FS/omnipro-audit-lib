# OmniPro Audit Library

A custom Java auditing library that uses Aspect-Oriented Programming (AOP) to simplify audit logging in Spring Boot applications.

## Features

- Easy-to-use `@Audit` annotation for method-level auditing
- Automatic capture of method parameters and return values
- IP address detection and logging
- Integration with RabbitMQ for audit event publishing
- Customizable metadata extraction

## Installation

To use this library in your project, add the following dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>com.omnipro.omniproauditlib</groupId>
  <artifactId>omnipro-audit-library</artifactId>
  <version>0.2.1</version>
</dependency>
```


## Setup

### Ensure you have set up a Personal Access Token (PAT) for Maven:

1. Go to your GitHub account settings.
2. Navigate to "Developer settings" > "Personal access tokens".
3. Generate a new token with at least `read:packages` scope.
4. Copy the generated token.

### Configure your Maven `settings.xml` file (usually located in `~/.m2/settings.xml`):

```xml
<settings>
  <servers>
    <server>
      <id>github</id>
      <username>YOUR_GITHUB_USERNAME</username>
      <password>YOUR_PERSONAL_ACCESS_TOKEN</password>
    </server>
  </servers>
</settings>
```

Replace YOUR_GITHUB_USERNAME and YOUR_PERSONAL_ACCESS_TOKEN with your actual GitHub username and the PAT you generated.

### Add the GitHub package registry to your project's `pom.xml`:

```xml
<repositories>
    <repository>
        <id>github</id>
        <name>GitHub Apache Maven Packages</name>
        <url>https://maven.pkg.github.com/Blusalt-FS/omnipro-audit-lib</url>
    </repository>
</repositories>
```

## Usage

### Add the `@Audit` annotation to methods you want to audit:

```java
@Audit(activity = "User Login", isMetaDataRequired = true)
public void loginUser(String username, String password) {
  // Method implementation
}
```


### Implement the `AuditMetadataExtractor` interface to provide custom metadata:

```java
@Component
public class CustomAuditMetadataExtractor implements AuditMetadataExtractor {
  @Override
  public AuditMetaData getAuditMetaData() {
    // Implement your logic to extract metadata
  }
}
```

### Configure RabbitMQ in your `application.properties` or `application.yml`:

```properties
spring.rabbitmq.addresses=amqp://your-rabbitmq-server:5672
```

## Configuration

The library uses the following configuration properties:

- `spring.application.name`: Used to set the service name in audit logs
- `spring.rabbitmq.addresses`: RabbitMQ server address

Ensure these are set in your application's configuration.
