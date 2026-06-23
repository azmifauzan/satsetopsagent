package executor

import (
	"strings"
	"testing"

	"github.com/satsetops/agent/internal/exec"
)

func TestBackupNowArchivesVolumeAndDatabaseThenUploads(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Outputs["stat -c %s /tmp/satsetops-backups/blog-12/archive.tgz"] = "2048"

	output, err := backupNow(map[string]any{
		"backup_run_id":    12,
		"application_name": "blog",
		"volume_name":      "blog_data",
		"storage_path":     "backups/1/1/demo.tgz",
		"upload_url":       "https://upload.example.test/demo",
		"database": map[string]any{
			"driver":    "mysql",
			"container": "blog-db",
			"database":  "blog",
			"username":  "root",
			"password":  "secret",
		},
	}, runner)
	if err != nil {
		t.Fatalf("backup_now: %v", err)
	}

	if !runner.HasCommandWithPrefix("docker run --rm -v blog_data:/source:ro") {
		t.Fatalf("expected volume backup command, got %#v", runner.Commands)
	}
	if !runner.HasCommandWithPrefix("sh -c docker exec 'blog-db' mysqldump -u'root' -p'secret' 'blog' > '/tmp/satsetops-backups/blog-12/database.sql'") {
		t.Fatalf("expected mysql dump command, got %#v", runner.Commands)
	}
	if !runner.HasCommand("curl -X PUT -T /tmp/satsetops-backups/blog-12/archive.tgz -- https://upload.example.test/demo") {
		t.Fatalf("expected upload command, got %#v", runner.Commands)
	}
	for _, cmd := range runner.Commands {
		if strings.Contains(cmd, "-C / ") {
			t.Fatalf("backup should not archive whole disk: %s", cmd)
		}
	}
	if !strings.Contains(output, "\"size_bytes\":2048") {
		t.Fatalf("unexpected result payload: %s", output)
	}
}

func TestRestoreBackupStopsRestoresAndStartsInOrder(t *testing.T) {
	runner := exec.NewFakeRunner()

	_, err := restoreBackup(map[string]any{
		"backup_run_id":    7,
		"application_name": "blog",
		"volume_name":      "blog_data",
		"download_url":     "https://download.example.test/demo",
		"database": map[string]any{
			"driver":    "pgsql",
			"container": "blog-db",
			"database":  "blog",
			"username":  "postgres",
			"password":  "secret",
		},
	}, runner)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	expected := []string{
		"curl -L -o /tmp/satsetops-restore/blog-7/archive.tgz -- https://download.example.test/demo",
		"docker stop -- blog",
		"docker run --rm -v blog_data:/target -v /tmp/satsetops-restore/blog-7:/backup busybox sh -c rm -rf /target/* /target/.[!.]* /target/..?* 2>/dev/null; tar -xzf /backup/volume.tar.gz -C /target",
		"sh -c docker exec -i -e 'PGPASSWORD=secret' 'blog-db' psql -U 'postgres' 'blog' < '/tmp/satsetops-restore/blog-7/database.sql'",
		"docker start -- blog",
	}

	lastIndex := -1
	for _, want := range expected {
		found := -1
		for i, cmd := range runner.Commands {
			if cmd == want {
				found = i
				break
			}
		}
		if found == -1 {
			t.Fatalf("missing command %q in %#v", want, runner.Commands)
		}
		if found <= lastIndex {
			t.Fatalf("command %q executed out of order: %#v", want, runner.Commands)
		}
		lastIndex = found
	}
}

func TestDumpDatabaseEscapesShellMetacharactersInCredentials(t *testing.T) {
	runner := exec.NewFakeRunner()

	err := dumpDatabase("/tmp/x", map[string]any{
		"driver":    "mysql",
		"container": "db",
		"database":  "blog",
		"username":  "root",
		"password":  `o'; rm -rf / #`,
	}, runner)
	if err != nil {
		t.Fatalf("dumpDatabase: %v", err)
	}

	cmd := runner.Commands[len(runner.Commands)-1]
	if !strings.HasPrefix(cmd, "sh -c docker exec 'db' mysqldump -u'root' -p'o'\\''; rm -rf / #' 'blog'") {
		t.Fatalf("password not safely quoted: %s", cmd)
	}
}

func TestBackupNowRejectsFlagLikeVolumeName(t *testing.T) {
	runner := exec.NewFakeRunner()

	_, err := backupNow(map[string]any{
		"backup_run_id":    1,
		"application_name": "blog",
		"volume_name":      "/etc:/etc",
		"storage_path":     "backups/1/1/demo.tgz",
		"upload_url":       "https://upload.example.test/demo",
	}, runner)
	if err == nil {
		t.Fatal("expected error for volume_name containing ':' (bind-mount escape)")
	}
}

func TestBackupNowRejectsNonHTTPUploadURL(t *testing.T) {
	runner := exec.NewFakeRunner()

	_, err := backupNow(map[string]any{
		"backup_run_id":    1,
		"application_name": "blog",
		"volume_name":      "blog_data",
		"storage_path":     "backups/1/1/demo.tgz",
		"upload_url":       "file:///etc/passwd",
	}, runner)
	if err == nil {
		t.Fatal("expected error for non-http(s) upload_url")
	}
}

func TestRestoreBackupRejectsFlagLikeApplicationName(t *testing.T) {
	runner := exec.NewFakeRunner()

	_, err := restoreBackup(map[string]any{
		"backup_run_id":    1,
		"application_name": "--privileged",
		"volume_name":      "blog_data",
		"download_url":     "https://download.example.test/demo",
	}, runner)
	if err == nil {
		t.Fatal("expected error for application_name starting with '-' (argv flag smuggling)")
	}
}

func TestDumpDatabaseRejectsFlagLikeContainerName(t *testing.T) {
	runner := exec.NewFakeRunner()

	err := dumpDatabase("/tmp/x", map[string]any{
		"driver":    "mysql",
		"container": "--privileged",
		"database":  "blog",
		"username":  "root",
		"password":  "secret",
	}, runner)
	if err == nil {
		t.Fatal("expected error for container name starting with '-'")
	}
}
