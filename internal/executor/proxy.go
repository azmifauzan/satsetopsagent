package executor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$`)

// setupNginxProxy deploys and hardens the jonasal/nginx-certbot reverse proxy
// container. Called once during the hardening sequence (after docker_harden),
// not lazily on first attach_domain_ssl. Idempotent: no-op if already running.
func setupNginxProxy(payload map[string]any, runner exec.Runner) (string, error) {
	email, _ := payload["email"].(string)
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("missing 'email' in payload (required for Certbot)")
	}

	if err := ensureNginxCertbotRunning(email, runner); err != nil {
		return "", err
	}

	return "nginx-certbot proxy deployed and hardened", nil
}

// attachDomainSSL writes a hardened vhost config for the domain and reloads
// nginx-certbot (which triggers certbot for the cert). Assumes setupNginxProxy
// has already been run during hardening.
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

	if err := writeVhostConfig(domain, portStr, runner); err != nil {
		return "", err
	}

	if _, err := runner.Run("docker", "kill", "--signal=HUP", "nginx-certbot"); err != nil {
		return "", fmt.Errorf("failed to reload nginx-certbot: %w", err)
	}

	return fmt.Sprintf("domain %s attached and SSL requested", domain), nil
}

// ensureNginxCertbotRunning starts the container if not already running.
// Idempotent — safe to call on re-hardening.
func ensureNginxCertbotRunning(email string, runner exec.Runner) error {
	if _, err := runner.Run("mkdir", "-p", "/etc/nginx/user_conf.d"); err != nil {
		return fmt.Errorf("create nginx user_conf.d: %w", err)
	}
	if _, err := runner.Run("mkdir", "-p", "/etc/letsencrypt"); err != nil {
		return fmt.Errorf("create letsencrypt dir: %w", err)
	}

	running, _ := runner.Run("docker", "inspect", "-f", "{{.State.Running}}", "nginx-certbot")
	switch strings.TrimSpace(running) {
	case "true":
		return nil
	case "false":
		if _, err := runner.Run("docker", "start", "nginx-certbot"); err != nil {
			return fmt.Errorf("start nginx-certbot: %w", err)
		}
		return nil
	}

	// Container does not exist — deploy it.
	_, err := runner.Run("docker", "run", "-d",
		"--name", "nginx-certbot",
		"--network", "host",
		"--restart", "unless-stopped",
		"-v", "/etc/nginx/user_conf.d:/etc/nginx/user_conf.d",
		"-v", "/etc/letsencrypt:/etc/letsencrypt",
		"-e", "CERTBOT_EMAIL="+email,
		"jonasal/nginx-certbot:latest",
	)
	if err != nil {
		return fmt.Errorf("deploy nginx-certbot: %w", err)
	}
	return nil
}

func writeVhostConfig(domain, portStr string, runner exec.Runner) error {
	if _, err := runner.Run("mkdir", "-p", "/etc/nginx/user_conf.d"); err != nil {
		return fmt.Errorf("create nginx user_conf.d: %w", err)
	}

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
	_, err := runner.RunWithStdin("bash", nginxConfig, "-c", fmt.Sprintf("cat > %s", configFile))
	return err
}
