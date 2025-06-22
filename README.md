# OIDC Implementation Tutorial - .NET 9 with Auth0 and AWS

A comprehensive tutorial demonstrating production-ready OIDC implementation using .NET 9 MVC and Minimal API with Auth0 as the external identity provider and AWS services integration.

## 🏗️ Architecture Overview

This solution implements a secure, scalable architecture with:
- **.NET 9 MVC Application**: Handles user authentication via Auth0's Authorization Code + PKCE flow
- **.NET 9 Minimal API**: Protected API using JWT bearer tokens
- **Auth0 Integration**: External OIDC provider for authentication
- **AWS Services**: OIDC federation for temporary credential access

```
┌─────────────────┐    OIDC Auth    ┌─────────────────┐
│   .NET 9 MVC    │◄──────────────►│     Auth0       │
│   Application   │                 │   (External     │
│                 │                 │    Provider)    │
└─────────┬───────┘                 └─────────────────┘
          │
          │ JWT Bearer Token
          │ (On behalf of user)
          ▼
┌─────────────────┐    OIDC Fed     ┌─────────────────┐
│  .NET 9 Minimal │◄──────────────►│  AWS Services   │
│      API        │                 │  (IAM, STS)     │
└─────────────────┘                 └─────────────────┘
```

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [AWS Setup](#aws-setup)
- [Auth0 Configuration](#auth0-configuration)
- [MVC Implementation](#mvc-implementation)
- [Minimal API Implementation](#minimal-api-implementation)
- [Configuration](#configuration)
- [Security Best Practices](#security-best-practices)
- [Architecture Decisions](#architecture-decisions)

## 🔧 Prerequisites

- .NET 9 SDK
- Auth0 account
- AWS account with IAM permissions
- Visual Studio 2022 or VS Code

## 🚀 Quick Start

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd oidc-implementation-tutorial
   dotnet restore
   ```

2. **Configure Auth0** (see [detailed steps](#auth0-configuration))
   - Create Regular Web Application
   - Configure API resource
   - Set callback URLs

3. **Setup AWS** (see [detailed steps](#aws-setup))
   - Create OIDC identity provider
   - Configure IAM roles and policies

4. **Update Configuration**
   ```bash
   # Update appsettings.json with your Auth0 and AWS settings
   ```

5. **Run Applications**
   ```bash
   # Terminal 1 - Run Minimal API
   cd src/OidcDemo.Api.Minimal
   dotnet run --urls="https://localhost:7001"
   
   # Terminal 2 - Run MVC App
   cd src/OidcDemo.Web.Mvc
   dotnet run --urls="https://localhost:5000"
   ```

## 📁 Project Structure

```
OidcImplementation.sln
├── src/
│   ├── OidcDemo.Web.Mvc/           # MVC Application
│   │   ├── Controllers/
│   │   ├── Views/
│   │   ├── Services/
│   │   ├── Handlers/
│   │   │   └── TokenForwardingHandler.cs
│   │   ├── Program.cs
│   │   └── appsettings.json
│   └── OidcDemo.Api.Minimal/       # Minimal API
│       ├── Endpoints/
│       ├── Models/
│       ├── Program.cs
│       └── appsettings.json
├── docs/
│   ├── setup-instructions.md
│   └── architecture-overview.md
└── README.md
```

## ☁️ AWS Setup

### Prerequisites: AWS Account Setup

#### Step 1: Create AWS Account
1. Go to [AWS Console](https://aws.amazon.com/)
2. Click "Create an AWS Account"
3. Follow the registration process (requires credit card for verification)
4. Complete email verification and phone verification

#### Step 2: Install and Configure AWS CLI
```bash
# Install AWS CLI v2 (Windows)
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi

# Install AWS CLI v2 (macOS)
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /

# Install AWS CLI v2 (Linux)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version
```

#### Step 3: Create IAM User with Required Permissions
1. **In AWS Console, go to IAM > Users > Create User**
2. **Username**: `oidc-tutorial-user`
3. **Attach policies directly**:
   - `IAMFullAccess` (for creating OIDC providers and roles)
   - `SecretsManagerFullAccess` (for storing Auth0 secrets)
4. **Create access key** for CLI access
5. **Download the credentials** (Access Key ID and Secret Access Key)

#### Step 4: Configure AWS CLI Credentials
```bash
# Configure AWS CLI with your credentials
aws configure

# Enter when prompted:
# AWS Access Key ID: [Your Access Key ID]
# AWS Secret Access Key: [Your Secret Access Key]  
# Default region name: us-east-1
# Default output format: json

# Verify configuration
aws sts get-caller-identity
```

### Prerequisites: Auth0 Information Collection

#### Step 5: Get Auth0 Domain and Client Information
Before setting up AWS OIDC, collect these from your Auth0 dashboard:

1. **Auth0 Domain**: Found in Auth0 Dashboard > Applications > [Your App] > Settings
   - Format: `your-tenant.auth0.com` or `your-tenant.us.auth0.com`

2. **Client ID**: Found in the same location
   - Format: `abc123def456ghi789jkl012`

3. **Get OIDC Discovery Document**:
   ```bash
   # Replace YOUR_AUTH0_DOMAIN with your actual domain
   curl https://YOUR_AUTH0_DOMAIN/.well-known/openid_configuration
   ```

4. **Get Auth0 Certificate Thumbprint**:
   ```bash
   # Get the certificate thumbprint (needed for AWS OIDC provider)
   echo | openssl s_client -servername YOUR_AUTH0_DOMAIN -connect YOUR_AUTH0_DOMAIN:443 2>/dev/null | openssl x509 -fingerprint -sha1 -noout | cut -d'=' -f2 | tr -d ':'
   ```

### AWS OIDC Configuration

#### Step 6: Create OIDC Identity Provider

```bash
# Replace placeholders with your actual values
aws iam create-open-id-connect-provider \
  --url https://YOUR_AUTH0_DOMAIN \
  --client-id-list "YOUR_AUTH0_CLIENT_ID" \
  --thumbprint-list "THUMBPRINT_FROM_STEP_5"

# Example:
# aws iam create-open-id-connect-provider \
#   --url https://dev-abc123.us.auth0.com \
#   --client-id-list "abc123def456ghi789jkl012" \
#   --thumbprint-list "1234567890abcdef1234567890abcdef12345678"
```

#### Step 7: Create Trust Policy JSON File

Create a file named `trust-policy.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/YOUR_AUTH0_DOMAIN"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "YOUR_AUTH0_DOMAIN:aud": "YOUR_AUTH0_CLIENT_ID",
          "YOUR_AUTH0_DOMAIN:iss": "https://YOUR_AUTH0_DOMAIN/"
        },
        "StringLike": {
          "YOUR_AUTH0_DOMAIN:sub": "auth0|*"
        }
      }
    }
  ]
}
```

**Get your AWS Account ID**:
```bash
aws sts get-caller-identity --query Account --output text
```

#### Step 8: Create IAM Role

```bash
# Create the IAM role
aws iam create-role \
  --role-name Auth0-OIDC-Role \
  --assume-role-policy-document file://trust-policy.json

# Attach a basic policy (customize based on your needs)
aws iam attach-role-policy \
  --role-name Auth0-OIDC-Role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

#### Step 9: Store Auth0 Secrets in AWS Secrets Manager

```bash
# Create secret for Auth0 client credentials
aws secretsmanager create-secret \
  --name "auth0/oidc-tutorial" \
  --description "Auth0 credentials for OIDC tutorial" \
  --secret-string '{
    "ClientId":"YOUR_AUTH0_CLIENT_ID",
    "ClientSecret":"YOUR_AUTH0_CLIENT_SECRET",
    "Authority":"https://YOUR_AUTH0_DOMAIN",
    "Audience":"https://api.yourdomain.com"
  }'
```

#### Step 10: Verify AWS Setup

```bash
# Verify OIDC provider was created
aws iam list-open-id-connect-providers

# Verify role was created
aws iam get-role --role-name Auth0-OIDC-Role

# Verify secret was created
aws secretsmanager describe-secret --secret-id "auth0/oidc-tutorial"

# Test assuming the role (this will fail until Auth0 is properly configured, but should show the role exists)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/Auth0-OIDC-Role \
  --role-session-name test-session \
  --web-identity-token "dummy-token"
```

### Required AWS Services
- **AWS STS**: Issues temporary credentials automatically
- **AWS IAM**: Manages identity providers and roles  
- **AWS Secrets Manager**: Stores Auth0 client secrets securely
- **Amazon CloudWatch**: Monitors authentication events

### Troubleshooting AWS Setup

**Common Issues:**

1. **"Access Denied" errors**: Ensure your IAM user has sufficient permissions
2. **"Invalid thumbprint"**: Re-generate the thumbprint using the OpenSSL command
3. **"Role already exists"**: Delete the existing role or use a different name
4. **"Secret already exists"**: Update the existing secret or use a different name

**Verify Prerequisites:**
```bash
# Check AWS CLI is configured
aws configure list

# Check you can access AWS services
aws iam get-user

# Check you have the right permissions
aws iam list-attached-user-policies --user-name YOUR_USERNAME
```

## 🔐 Auth0 Configuration

### Prerequisites: Auth0 Account Setup

#### Step 1: Create Auth0 Account
1. Go to [Auth0](https://auth0.com/) and click "Sign Up"
2. Choose your preferred signup method (email, Google, GitHub, etc.)
3. Complete the verification process
4. **Choose your tenant domain** (this becomes YOUR_AUTH0_DOMAIN)
   - Format: `your-chosen-name.auth0.com` (US) or `your-chosen-name.eu.auth0.com` (EU)
   - **Note**: This cannot be changed later, choose carefully!

#### Step 2: Complete Auth0 Initial Setup
1. **Choose your use case**: "I'm building a B2B SaaS application"
2. **Account type**: "Personal" (for tutorial) or "Company" 
3. **Role**: "Developer" or "Architect"
4. Complete the onboarding tour

### Auth0 Application Configuration

#### Step 3: Create Regular Web Application

1. **In Auth0 Dashboard**: Applications > Create Application
2. **Name**: "OIDC Tutorial MVC App"
3. **Application Type**: "Regular Web Applications"
4. **Technology**: ".NET (Core)"
5. Click "Create"

#### Step 4: Configure Application Settings

**In the application settings tab**:

```json
{
  "Application Type": "Regular Web Application",
  "Token Endpoint Authentication Method": "Client Secret Basic",
  "Application Login URI": "https://localhost:5000",
  "Allowed Callback URLs": [
    "https://localhost:5000/signin-oidc",
    "https://yourdomain.com/signin-oidc"
  ],
  "Allowed Logout URLs": [
    "https://localhost:5000/signout-callback-oidc", 
    "https://yourdomain.com/signout-callback-oidc"
  ],
  "Allowed Web Origins": [
    "https://localhost:5000",
    "https://yourdomain.com"
  ]
}
```

**Advanced Settings**:
- **Grant Types**: 
  - ✅ Authorization Code
  - ✅ Refresh Token
  - ❌ Implicit (deprecated)
  - ❌ Client Credentials (not needed for this flow)

#### Step 5: Save Critical Information
**Copy these values** (you'll need them for configuration):
- **Domain**: `your-tenant.auth0.com`
- **Client ID**: `abc123def456ghi789jkl012`  
- **Client Secret**: `xyz789abc123def456ghi012jkl345mno678pqr901` (click "Show")

### Auth0 API Resource Configuration

#### Step 6: Create API Resource for Minimal API

1. **In Auth0 Dashboard**: Applications > APIs > Create API
2. **Name**: "Weather API"
3. **Identifier**: `https://api.yourdomain.com` 
   - ⚠️ **Important**: This becomes the JWT audience claim
   - Use a URL format even if it's not a real URL
4. **Signing Algorithm**: RS256
5. Click "Create"

#### Step 7: Configure API Settings

**In the API settings**:
- **Enable RBAC**: ✅ True
- **Add Permissions in Access Token**: ✅ True
- **Allow Skipping User Consent**: ✅ True (for development)
- **Allow Offline Access**: ✅ True (enables refresh tokens)

#### Step 8: Add API Scopes/Permissions

**In the API Permissions tab**, add:

| Scope Value | Description |
|-------------|-------------|
| `read:weather` | Read weather forecast data |
| `write:weather` | Create and modify weather data |
| `admin:weather` | Full administrative access |

#### Step 9: Authorize Application to Use API

1. **Go to**: Applications > [Your MVC App] > APIs tab
2. **Click**: "Authorize" next to your Weather API
3. **Select scopes** to authorize:
   - ✅ `read:weather`
   - ✅ `write:weather`
4. **Click**: "Update"

### Auth0 Advanced Configuration

#### Step 10: Configure Custom Claims (Optional)

**Create a Rule** for adding custom claims to tokens:

1. **Go to**: Auth Pipeline > Rules > Create Rule
2. **Template**: "Empty rule"
3. **Name**: "Add User Roles to Token"

```javascript
function addRolesToToken(user, context, callback) {
  const namespace = 'https://api.yourdomain.com/';
  const assignedRoles = (context.authorization || {}).roles;
  
  let idTokenClaims = context.idToken || {};
  let accessTokenClaims = context.accessToken || {};
  
  idTokenClaims[`${namespace}roles`] = assignedRoles;
  accessTokenClaims[`${namespace}roles`] = assignedRoles;
  
  context.idToken = idTokenClaims;
  context.accessToken = accessTokenClaims;
  
  callback(null, user, context);
}
```

#### Step 11: Test Auth0 Configuration

**Verify your setup**:

1. **Test the OIDC discovery endpoint**:
   ```bash
   curl https://YOUR_AUTH0_DOMAIN/.well-known/openid_configuration
   ```

2. **Verify expected response includes**:
   ```json
   {
     "issuer": "https://YOUR_AUTH0_DOMAIN/",
     "authorization_endpoint": "https://YOUR_AUTH0_DOMAIN/authorize",
     "token_endpoint": "https://YOUR_AUTH0_DOMAIN/oauth/token",
     "userinfo_endpoint": "https://YOUR_AUTH0_DOMAIN/userinfo",
     "jwks_uri": "https://YOUR_AUTH0_DOMAIN/.well-known/jwks.json"
   }
   ```

### Troubleshooting Auth0 Setup

**Common Issues:**

1. **"Invalid callback URL"**: Ensure exact match including https:// and no trailing slash
2. **"Access denied"**: Check that the application is authorized for the API
3. **"Invalid audience"**: Verify API identifier matches the audience in your .NET configuration
4. **"Invalid scope"**: Ensure scopes are defined in the API and authorized for the application

**Test Authentication Flow**:
```bash
# Test authorization endpoint (paste in browser)
https://YOUR_AUTH0_DOMAIN/authorize?
  response_type=code&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://localhost:5000/signin-oidc&
  scope=openid profile email read:weather&
  state=test123&
  code_challenge=YOUR_PKCE_CHALLENGE&
  code_challenge_method=S256
```

## 🌐 MVC Implementation

### Key Dependencies
```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.OpenIdConnect" Version="9.0.5" />
<PackageReference Include="Microsoft.AspNetCore.Authentication.Cookies" Version="9.0.5" />
```

### Program.cs Configuration
```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// Configure Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.AccessDeniedPath = "/Home/AccessDenied";
    options.SameSite = SameSiteMode.Strict;
    options.SecurePolicy = CookieSecurePolicy.Always;
})
.AddOpenIdConnect(options =>
{
    options.Authority = builder.Configuration["Auth0:Authority"];
    options.ClientId = builder.Configuration["Auth0:ClientId"];
    options.ClientSecret = builder.Configuration["Auth0:ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    
    // Enable PKCE
    options.UsePkce = true;
    
    // Configure scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("read:weather");
    
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
});

// Configure HTTP Client for API calls
builder.Services.AddHttpClient("WeatherApi", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiSettings:BaseUrl"]!);
})
.AddHttpMessageHandler<TokenForwardingHandler>();

builder.Services.AddTransient<TokenForwardingHandler>();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
```

### Token Forwarding Handler
```csharp
public class TokenForwardingHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TokenForwardingHandler> _logger;

    public TokenForwardingHandler(IHttpContextAccessor httpContextAccessor, 
        ILogger<TokenForwardingHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, 
        CancellationToken cancellationToken)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        
        if (httpContext?.User.Identity?.IsAuthenticated == true)
        {
            var accessToken = await httpContext.GetTokenAsync("access_token");
            
            if (!string.IsNullOrEmpty(accessToken))
            {
                request.Headers.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                
                _logger.LogDebug("Added bearer token to API request");
            }
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
```

## 🔌 Minimal API Implementation

### Program.cs Configuration
```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure JWT Bearer Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Auth0:Authority"];
        options.Audience = builder.Configuration["Auth0:Audience"];
        options.RequireHttpsMetadata = true;
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromMinutes(5),
            NameClaimType = "sub"
        };
    });

// Configure Authorization Policies
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("ReadWeather", policy =>
        policy.RequireAuthenticatedUser()
              .RequireClaim("scope", "read:weather"))
    .AddPolicy("WriteWeather", policy =>
        policy.RequireAuthenticatedUser()
              .RequireClaim("scope", "write:weather"));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Protected API Endpoints
app.MapGet("/weather-forecast", () =>
{
    return GetWeatherForecast();
})
.RequireAuthorization("ReadWeather")
.WithName("GetWeatherForecast")
.WithOpenApi();

app.MapPost("/weather-forecast", (WeatherForecast forecast) =>
{
    return Results.Created($"/weather-forecast/{forecast.Date}", forecast);
})
.RequireAuthorization("WriteWeather")
.WithName("CreateWeatherForecast")
.WithOpenApi();

app.Run();

static WeatherForecast[] GetWeatherForecast()
{
    var summaries = new[] { "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching" };
    
    return Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
}

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
```

## ⚙️ Configuration

### MVC Application (appsettings.json)
```json
{
  "Auth0": {
    "Authority": "https://your-domain.auth0.com",
    "ClientId": "your-mvc-client-id",
    "ClientSecret": "your-client-secret"
  },
  "ApiSettings": {
    "BaseUrl": "https://localhost:7001"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore.Authentication": "Debug"
    }
  }
}
```

### Minimal API (appsettings.json)
```json
{
  "Auth0": {
    "Authority": "https://your-domain.auth0.com",
    "Audience": "https://api.yourdomain.com"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore.Authentication": "Debug"
    }
  }
}
```

## 🔒 Security Best Practices

### OAuth 2.1 Compliance
- ✅ PKCE mandatory for authorization code flow
- ✅ Exact string matching for redirect URI validation
- ✅ Bearer tokens never in query strings
- ✅ Short-lived access tokens with refresh token rotation
- ✅ RS256 algorithm enforcement for JWT signatures

### Production Security Checklist
- [ ] Enable HSTS headers and enforce HTTPS
- [ ] Implement proper CORS policies
- [ ] Use secure cookie settings (HttpOnly, Secure, SameSite)
- [ ] Store secrets in AWS Secrets Manager
- [ ] Enable comprehensive logging without exposing sensitive data
- [ ] Implement refresh token rotation
- [ ] Validate all JWT claims (issuer, audience, expiration)
- [ ] Use short token lifetimes (1 hour for access tokens)

## 🏛️ Architecture Decisions

This tutorial makes specific architectural choices to demonstrate best practices and modern security requirements:

### 1. Why Auth0 over AWS Cognito for External OIDC?
**Answer**: Auth0 provides superior OIDC compliance, better developer experience, platform-agnostic design, and advanced security features. It excels in external identity scenarios with extensive integration capabilities, while AWS Cognito is optimized for AWS-native applications.

### 2. Why Authorization Code + PKCE flow for desktop-like applications?
**Answer**: Authorization Code + PKCE is the security best practice for all OAuth 2.1 applications, including desktop-like scenarios. PKCE provides protection against authorization code injection and CSRF attacks while supporting refresh tokens. It's mandatory in OAuth 2.1 and offers better security than the deprecated implicit flow.

### 3. Why JWT bearer tokens for "on behalf of" user capabilities?
**Answer**: JWT bearer tokens enable stateless authentication, carry user context across distributed services, and support scalable microservice architectures. They provide a clear way to implement "on behalf of" user patterns where one service calls another while maintaining the original user's identity and permissions.

## 📚 Additional Resources

- [OAuth 2.1 Specification](https://oauth.net/2.1/)
- [Auth0 OIDC Documentation](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce)
- [AWS OIDC Federation Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html)
- [.NET 9 Authentication Documentation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/)

