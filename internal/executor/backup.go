package executor

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/exec"
)

// resourceNameRegex constrains container/volume/database names used as
// docker/mysqldump/pg_dump arguments. Stricter than deploy.go's nameRegex —
// must start with an alnum so a value like "--privileged" or "-v" can't be
// mistaken for a flag by docker's argv parser, and "/" / ":" are rejected so
// a volume_name can't smuggle a bind mount of an arbitrary host path.
var resourceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`)

func validateResourceName(field, value string) error {
	if !resourceNameRegex.MatchString(value) {
		return fmt.Errorf("invalid %s format", field)
	}

	return nil
}

func validateHTTPURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid %s: must be an http(s) URL", field)
	}

	return nil
}

func backupNow(payload map[string]any, runner exec.Runner) (string, error) {
	appName, err := requireString(payload, "application_name")
	if err != nil {
		return "", err
	}
	if err := validateResourceName("application_name", appName); err != nil {
		return "", err
	}
	volumeName, err := requireString(payload, "volume_name")
	if err != nil {
		return "", err
	}
	if err := validateResourceName("volume_name", volumeName); err != nil {
		return "", err
	}
	storagePath, err := requireString(payload, "storage_path")
	if err != nil {
		return "", err
	}
	uploadURL, err := requireString(payload, "upload_url")
	if err != nil {
		return "", err
	}
	if err := validateHTTPURL("upload_url", uploadURL); err != nil {
		return "", err
	}

	runID := stringOrDefault(payload["backup_run_id"], "run")
	tempDir := fmt.Sprintf("/tmp/satsetops-backups/%s-%s", appName, runID)
	archivePath := fmt.Sprintf("%s/archive.tgz", tempDir)

	if _, err := runner.Run("mkdir", "-p", tempDir); err != nil {
		return "", fmt.Errorf("create backup temp dir: %w", err)
	}

	if _, err := runner.Run(
		"docker", "run", "--rm",
		"-v", volumeName+":/source:ro",
		"-v", tempDir+":/backup",
		"busybox",
		"tar", "-czf", "/backup/volume.tar.gz", "-C", "/source", ".",
	); err != nil {
		return "", fmt.Errorf("backup volume %s: %w", volumeName, err)
	}

	dbIncluded := false
	if database, ok := payload["database"].(map[string]any); ok && len(database) > 0 {
		if err := dumpDatabase(tempDir, database, runner); err != nil {
			return "", err
		}
		dbIncluded = true
	}

	if _, err := runner.Run("tar", "-czf", archivePath, "-C", tempDir, "."); err != nil {
		return "", fmt.Errorf("archive backup: %w", err)
	}

	if _, err := runner.Run("curl", "-X", "PUT", "-T", archivePath, "--", uploadURL); err != nil {
		return "", fmt.Errorf("upload backup archive: %w", err)
	}

	sizeOutput, err := runner.Run("stat", "-c", "%s", archivePath)
	if err != nil {
		return "", fmt.Errorf("stat backup archive: %w", err)
	}

	sizeBytes, _ := strconv.ParseInt(sizeOutput, 10, 64)

	result, err := json.Marshal(map[string]any{
		"storage_path": storagePath,
		"size_bytes":   sizeBytes,
		"database":     dbIncluded,
		"volume_name":  volumeName,
	})
	if err != nil {
		return "", fmt.Errorf("encode backup result: %w", err)
	}

	return string(result), nil
}

func restoreBackup(payload map[string]any, runner exec.Runner) (string, error) {
	appName, err := requireString(payload, "application_name")
	if err != nil {
		return "", err
	}
	if err := validateResourceName("application_name", appName); err != nil {
		return "", err
	}
	volumeName, err := requireString(payload, "volume_name")
	if err != nil {
		return "", err
	}
	if err := validateResourceName("volume_name", volumeName); err != nil {
		return "", err
	}
	downloadURL, err := requireString(payload, "download_url")
	if err != nil {
		return "", err
	}
	if err := validateHTTPURL("download_url", downloadURL); err != nil {
		return "", err
	}

	runID := stringOrDefault(payload["backup_run_id"], "run")
	tempDir := fmt.Sprintf("/tmp/satsetops-restore/%s-%s", appName, runID)
	archivePath := fmt.Sprintf("%s/archive.tgz", tempDir)

	if _, err := runner.Run("mkdir", "-p", tempDir); err != nil {
		return "", fmt.Errorf("create restore temp dir: %w", err)
	}

	if _, err := runner.Run("curl", "-L", "-o", archivePath, "--", downloadURL); err != nil {
		return "", fmt.Errorf("download backup archive: %w", err)
	}

	if _, err := runner.Run("tar", "-xzf", archivePath, "-C", tempDir); err != nil {
		return "", fmt.Errorf("extract backup archive: %w", err)
	}

	if _, err := runner.Run("docker", "stop", "--", appName); err != nil {
		return "", fmt.Errorf("stop app container %s: %w", appName, err)
	}

	restoreCmd := fmt.Sprintf("rm -rf /target/* /target/.[!.]* /target/..?* 2>/dev/null; tar -xzf /backup/volume.tar.gz -C /target")
	if _, err := runner.Run(
		"docker", "run", "--rm",
		"-v", volumeName+":/target",
		"-v", tempDir+":/backup",
		"busybox",
		"sh", "-c", restoreCmd,
	); err != nil {
		return "", fmt.Errorf("restore volume %s: %w", volumeName, err)
	}

	if database, ok := payload["database"].(map[string]any); ok && len(database) > 0 {
		if err := restoreDatabase(tempDir, database, runner); err != nil {
			return "", err
		}
	}

	if _, err := runner.Run("docker", "start", "--", appName); err != nil {
		return "", fmt.Errorf("start app container %s: %w", appName, err)
	}

	return fmt.Sprintf("restored %s from backup", appName), nil
}

func dumpDatabase(tempDir string, database map[string]any, runner exec.Runner) error {
	driver, err := requireMapString(database, "driver")
	if err != nil {
		return err
	}
	container, err := requireMapString(database, "container")
	if err != nil {
		return err
	}
	if err := validateResourceName("database.container", container); err != nil {
		return err
	}
	dbName, err := requireMapString(database, "database")
	if err != nil {
		return err
	}
	if err := validateResourceName("database.database", dbName); err != nil {
		return err
	}
	username, err := requireMapString(database, "username")
	if err != nil {
		return err
	}
	password, err := requireMapString(database, "password")
	if err != nil {
		return err
	}

	target := fmt.Sprintf("%s/database.sql", tempDir)

	switch driver {
	case "mysql":
		cmd := fmt.Sprintf("docker exec %s mysqldump -u%s -p%s %s > %s",
			shellQuote(container), shellQuote(username), shellQuote(password), shellQuote(dbName), shellQuote(target))
		if _, err := runner.Run("sh", "-c", cmd); err != nil {
			return fmt.Errorf("dump mysql database: %w", err)
		}
	case "pgsql":
		cmd := fmt.Sprintf("docker exec -e %s %s pg_dump -U %s %s > %s",
			shellQuote("PGPASSWORD="+password), shellQuote(container), shellQuote(username), shellQuote(dbName), shellQuote(target))
		if _, err := runner.Run("sh", "-c", cmd); err != nil {
			return fmt.Errorf("dump pgsql database: %w", err)
		}
	default:
		return fmt.Errorf("unsupported database driver: %s", driver)
	}

	return nil
}

func restoreDatabase(tempDir string, database map[string]any, runner exec.Runner) error {
	driver, err := requireMapString(database, "driver")
	if err != nil {
		return err
	}
	container, err := requireMapString(database, "container")
	if err != nil {
		return err
	}
	if err := validateResourceName("database.container", container); err != nil {
		return err
	}
	dbName, err := requireMapString(database, "database")
	if err != nil {
		return err
	}
	if err := validateResourceName("database.database", dbName); err != nil {
		return err
	}
	username, err := requireMapString(database, "username")
	if err != nil {
		return err
	}
	password, err := requireMapString(database, "password")
	if err != nil {
		return err
	}

	source := fmt.Sprintf("%s/database.sql", tempDir)

	switch driver {
	case "mysql":
		cmd := fmt.Sprintf("docker exec -i %s mysql -u%s -p%s %s < %s",
			shellQuote(container), shellQuote(username), shellQuote(password), shellQuote(dbName), shellQuote(source))
		if _, err := runner.Run("sh", "-c", cmd); err != nil {
			return fmt.Errorf("restore mysql database: %w", err)
		}
	case "pgsql":
		cmd := fmt.Sprintf("docker exec -i -e %s %s psql -U %s %s < %s",
			shellQuote("PGPASSWORD="+password), shellQuote(container), shellQuote(username), shellQuote(dbName), shellQuote(source))
		if _, err := runner.Run("sh", "-c", cmd); err != nil {
			return fmt.Errorf("restore pgsql database: %w", err)
		}
	default:
		return fmt.Errorf("unsupported database driver: %s", driver)
	}

	return nil
}

// shellQuote wraps a value in single quotes for safe interpolation into a
// `sh -c` string — driver/container/dbName/username/password all originate
// from the app owner's own env config, so a `"`, `$()`, or `;` in there must
// not be interpreted as shell syntax.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func requireString(payload map[string]any, key string) (string, error) {
	value, ok := payload[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("missing or invalid %q in payload", key)
	}

	return value, nil
}

func requireMapString(payload map[string]any, key string) (string, error) {
	value, ok := payload[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("missing or invalid %q in database payload", key)
	}

	return value, nil
}

func stringOrDefault(value any, fallback string) string {
	switch v := value.(type) {
	case string:
		if v != "" {
			return v
		}
	case float64:
		return strconv.Itoa(int(v))
	case int:
		return strconv.Itoa(v)
	}

	return fallback
}
