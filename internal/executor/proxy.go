package executor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$`)
var containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

const proxyNetwork = "satsetops-proxy"

// setupNginxProxy deploys and hardens the jonasal/nginx-certbot reverse proxy
// container on the satsetops-proxy Docker network. Called once during hardening
// (after docker_harden), not lazily on first attach_domain_ssl. Idempotent.
func setupNginxProxy(payload map[string]any, runner exec.Runner) (string, error) {
	email, _ := payload["email"].(string)
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("missing 'email' in payload (required for Certbot)")
	}

	if err := ensureProxyNetwork(runner); err != nil {
		return "", err
	}
	if err := ensureNginxCertbotRunning(email, runner); err != nil {
		return "", err
	}

	return "nginx-certbot proxy deployed and hardened", nil
}

// attachDomainSSL writes a hardened vhost config for the domain and reloads
// nginx-certbot. Traffic flows: nginx-certbot → container_name:port inside
// the satsetops-proxy Docker network. Assumes setupNginxProxy already ran.
func attachDomainSSL(payload map[string]any, runner exec.Runner) (string, error) {
	domain, ok := payload["domain"].(string)
	if !ok || domain == "" {
		return "", fmt.Errorf("missing or invalid 'domain' in payload")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRegex.MatchString(domain) {
		return "", fmt.Errorf("invalid domain format (must be FQDN)")
	}

	containerName, _ := payload["container_name"].(string)
	containerName = strings.TrimSpace(containerName)
	if containerName == "" {
		return "", fmt.Errorf("missing 'container_name' in payload")
	}
	if !containerNameRegex.MatchString(containerName) {
		return "", fmt.Errorf("invalid container_name (must match Docker name format)")
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

	if err := writeVhostConfig(domain, containerName, portStr, runner); err != nil {
		return "", err
	}

	if _, err := runner.Run("docker", "kill", "--signal=HUP", "nginx-certbot"); err != nil {
		return "", fmt.Errorf("failed to reload nginx-certbot: %w", err)
	}

	return fmt.Sprintf("domain %s attached and SSL requested", domain), nil
}

// ensureProxyNetwork creates the satsetops-proxy Docker bridge network if it
// doesn't already exist. Idempotent.
func ensureProxyNetwork(runner exec.Runner) error {
	out, _ := runner.Run("docker", "network", "inspect", proxyNetwork)
	if strings.Contains(out, proxyNetwork) {
		return nil
	}
	if _, err := runner.Run("docker", "network", "create", proxyNetwork); err != nil {
		return fmt.Errorf("create %s network: %w", proxyNetwork, err)
	}
	return nil
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
	// --userns=host: certbot inside the container runs as root; without this,
	// Docker user-namespace remapping prevents writes to the /etc/letsencrypt
	// bind-mount (owned by real root on the host).
	// --network: joins the satsetops-proxy bridge so it can reach app containers
	// by name via proxy_pass.
	_, err := runner.Run("docker", "run", "-d",
		"--name", "nginx-certbot",
		"-p", "80:80",
		"-p", "443:443",
		"--userns=host",
		"--network", proxyNetwork,
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

func writeVhostConfig(domain, containerName, portStr string, runner exec.Runner) error {
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
        proxy_pass http://%s:%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`, zoneName, domain, domain, domain, domain, zoneName, containerName, portStr)

	configFile := fmt.Sprintf("/etc/nginx/user_conf.d/%s.conf", domain)
	_, err := runner.RunWithStdin("bash", nginxConfig, "-c", fmt.Sprintf("cat > %s", configFile))
	return err
}
