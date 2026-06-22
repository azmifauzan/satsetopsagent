package executor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$`)

func attachDomainSSL(payload map[string]any, runner exec.Runner) (string, error) {
	domain, ok := payload["domain"].(string)
	if !ok || domain == "" {
		return "", fmt.Errorf("missing or invalid 'domain' in payload")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRegex.MatchString(domain) {
		return "", fmt.Errorf("invalid domain format (must be FQDN)")
	}

	var portStr string
	switch p := payload["port"].(type) {
	case string:
		portStr = p
	case float64:
		portStr = strconv.Itoa(int(p))
	case int:
		portStr = strconv.Itoa(p)
	default:
		return "", fmt.Errorf("missing or invalid 'port' in payload")
	}

	portVal, err := strconv.Atoi(portStr)
	if err != nil || portVal < 1 || portVal > 65535 {
		return "", fmt.Errorf("invalid port value: %s", portStr)
	}

	email, _ := payload["email"].(string)
	email = strings.TrimSpace(email)
	if email == "" {
		email = "admin@" + domain
	}

	// 1. Ensure directories exist on host
	_, err = runner.Run("mkdir", "-p", "/etc/nginx/user_conf.d")
	if err != nil {
		return "", fmt.Errorf("failed to create nginx user_conf.d directory: %w", err)
	}
	_, err = runner.Run("mkdir", "-p", "/etc/letsencrypt")
	if err != nil {
		return "", fmt.Errorf("failed to create letsencrypt directory: %w", err)
	}

	// 2. Write Nginx config
	zoneName := strings.ReplaceAll(domain, ".", "_") + "_limit"
	nginxConfig := fmt.Sprintf(`limit_req_zone $binary_remote_addr zone=%s:10m rate=10r/s;

server {
    listen 80;
    server_name %s;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name %s;

    ssl_certificate /etc/letsencrypt/live/%s/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/%s/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline' 'unsafe-eval';" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    server_tokens off;

    limit_req zone=%s burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`, zoneName, domain, domain, domain, domain, zoneName, portStr)

	configFile := fmt.Sprintf("/etc/nginx/user_conf.d/%s.conf", domain)
	// Write configuration file
	_, err = runner.Run("bash", "-c", fmt.Sprintf("echo -e '%s' > %s", strings.ReplaceAll(nginxConfig, "\n", "\\n"), configFile))
	if err != nil {
		return "", fmt.Errorf("failed to write nginx config file: %w", err)
	}

	// 3. Ensure nginx-certbot container is deployed and running
	runningStatus, err := runner.Run("docker", "inspect", "-f", "{{.State.Running}}", "nginx-certbot")
	if err != nil {
		// Container doesn't exist, deploy it
		_, err = runner.Run("docker", "run", "-d",
			"--name", "nginx-certbot",
			"--network", "host",
			"--restart", "unless-stopped",
			"-v", "/etc/nginx/user_conf.d:/etc/nginx/user_conf.d",
			"-v", "/etc/letsencrypt:/etc/letsencrypt",
			"-e", "CERTBOT_EMAIL="+email,
			"jonasal/nginx-certbot:latest",
		)
		if err != nil {
			return "", fmt.Errorf("failed to deploy nginx-certbot container: %w", err)
		}
	} else if strings.TrimSpace(runningStatus) != "true" {
		// Container exists but not running, start it
		_, err = runner.Run("docker", "start", "nginx-certbot")
		if err != nil {
			return "", fmt.Errorf("failed to start nginx-certbot container: %w", err)
		}
	}

	// 4. Reload Nginx configuration to apply changes and trigger certbot
	_, err = runner.Run("docker", "kill", "--signal=HUP", "nginx-certbot")
	if err != nil {
		return "", fmt.Errorf("failed to reload nginx-certbot config: %w", err)
	}

	return fmt.Sprintf("domain %s attached and SSL requested", domain), nil
}
