package audit

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	projectCatalogSchemaV1 = "ward-audit-project-catalog/v1"
	projectMarkerSchemaV1  = "ward-audit-project/v1"
	projectCatalogFile     = "projects.json"
	projectCatalogLockFile = "projects.lock"
	projectMarkerFile      = "project.json"
	projectLockFile        = "events.lock"
)

type projectCatalog struct {
	Schema    string    `json:"schema"`
	Projects  []string  `json:"projects"`
	UpdatedAt time.Time `json:"updated_at"`
	RecordMAC string    `json:"record_mac"`
}

type projectMarker struct {
	Schema    string    `json:"schema"`
	ProjectID string    `json:"project_id"`
	CreatedAt time.Time `json:"created_at"`
	RecordMAC string    `json:"record_mac"`
}

func catalogWithoutMAC(catalog projectCatalog) projectCatalog {
	catalog.RecordMAC = ""
	return catalog
}

func markerWithoutMAC(marker projectMarker) projectMarker {
	marker.RecordMAC = ""
	return marker
}

func openAuditIdentity(stateDir, projectsDir string, create, initialize bool, now func() time.Time, randomSource io.Reader) ([]byte, error) {
	return openAuditIdentityContext(context.Background(), stateDir, projectsDir, create, initialize, now, randomSource)
}

func openAuditIdentityContext(ctx context.Context, stateDir, projectsDir string, create, initialize bool, now func() time.Time, randomSource io.Reader) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(stateDir, "master.key")
	catalogPath := filepath.Join(stateDir, projectCatalogFile)
	_, keyErr := os.Lstat(keyPath)
	if errors.Is(keyErr, os.ErrNotExist) {
		catalogExists, err := pathExists(catalogPath)
		if err != nil {
			return nil, err
		}
		projectIDs, err := listProjectDirectoryIDsContext(ctx, projectsDir)
		if err != nil {
			return nil, err
		}
		if catalogExists || len(projectIDs) > 0 {
			return nil, integrity(0, "missing_master_key")
		}
		if !create {
			return nil, ErrNotInitialized
		}
		// NewStore may initialize only a state directory that did not exist when
		// the call began. An existing directory without its key is evidence of
		// deletion or an incomplete/legacy installation, not a fresh store.
		if !initialize {
			return nil, integrity(0, "missing_master_key")
		}
	}
	var key []byte
	var err error
	if create {
		key, err = loadOrCreateMasterKeyContext(ctx, keyPath, randomSource)
	} else {
		key, err = loadExistingMasterKeyContext(ctx, keyPath)
	}
	if err != nil {
		return nil, err
	}

	catalogExists, err := pathExists(catalogPath)
	if err != nil {
		zeroBytes(key)
		return nil, err
	}
	if !catalogExists {
		projectIDs, listErr := listProjectDirectoryIDsContext(ctx, projectsDir)
		if listErr != nil {
			zeroBytes(key)
			return nil, listErr
		}
		if len(projectIDs) > 0 {
			zeroBytes(key)
			return nil, integrity(0, "missing_project_catalog")
		}
		if !initialize {
			zeroBytes(key)
			return nil, integrity(0, "missing_project_catalog")
		}
		if !create {
			zeroBytes(key)
			return nil, ErrNotInitialized
		}
		catalog := projectCatalog{
			Schema:    projectCatalogSchemaV1,
			Projects:  []string{},
			UpdatedAt: now().UTC(),
		}
		if err := writeProjectCatalogContext(ctx, catalogPath, key, catalog); err != nil {
			zeroBytes(key)
			return nil, err
		}
	}
	catalog, err := readProjectCatalogContext(ctx, catalogPath, key)
	if err != nil {
		zeroBytes(key)
		return nil, err
	}
	if err := validateCatalogLayoutContext(ctx, projectsDir, key, catalog); err != nil {
		zeroBytes(key)
		return nil, err
	}
	return key, nil
}

func (s *Store) verifyCatalog(ctx context.Context) (projectCatalog, error) {
	if err := contextError(ctx); err != nil {
		return projectCatalog{}, err
	}
	lock, err := acquireFileLock(ctx, s.catalogLockPath, lockShared, s.lockTimeout, false)
	if err != nil {
		return projectCatalog{}, err
	}
	defer lock.release()
	if err := s.verifyMasterKeyContext(ctx); err != nil {
		return projectCatalog{}, err
	}
	if err := contextError(ctx); err != nil {
		return projectCatalog{}, err
	}
	catalog, err := readProjectCatalogContext(ctx, s.catalogPath, s.masterKey)
	if err != nil {
		return projectCatalog{}, err
	}
	if err := validateCatalogLayoutContext(ctx, s.projectsDir, s.masterKey, catalog); err != nil {
		return projectCatalog{}, err
	}
	return catalog, nil
}

func (s *Store) ensureRegisteredProject(ctx context.Context, project projectState) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	lock, err := acquireFileLock(ctx, s.catalogLockPath, lockExclusive, s.lockTimeout, false)
	if err != nil {
		return err
	}
	defer lock.release()
	if err := s.verifyMasterKeyContext(ctx); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	catalog, err := readProjectCatalogContext(ctx, s.catalogPath, s.masterKey)
	if err != nil {
		return err
	}
	if err := validateCatalogLayoutContext(ctx, s.projectsDir, s.masterKey, catalog); err != nil {
		return err
	}
	if catalogHasProject(catalog, project.id) {
		return nil
	}

	if err := ensurePrivateDirectoryContext(ctx, project.dir); err != nil {
		return fmt.Errorf("prepare project audit directory: %w", err)
	}
	created := true
	cleanup := func() {
		if !created {
			return
		}
		_ = os.Remove(project.markerPath)
		_ = os.Remove(project.lockPath)
		_ = os.Remove(project.dir)
	}
	projectLock, err := acquireFileLock(ctx, project.lockPath, lockExclusive, s.lockTimeout, true)
	if err != nil {
		cleanup()
		return err
	}
	projectLock.release()
	marker := projectMarker{
		Schema:    projectMarkerSchemaV1,
		ProjectID: project.id,
		CreatedAt: s.now().UTC(),
	}
	marker.RecordMAC, err = signJSONContext(ctx, project.key, "ward-audit-project/v1", markerWithoutMAC(marker))
	if err != nil {
		cleanup()
		return fmt.Errorf("sign audit project marker: %w", err)
	}
	if err := writePrivateJSONContext(ctx, project.dir, project.markerPath, marker); err != nil {
		cleanup()
		return fmt.Errorf("write audit project marker: %w", err)
	}
	if err := contextError(ctx); err != nil {
		cleanup()
		return err
	}
	catalog.Projects = append(catalog.Projects, project.id)
	sort.Strings(catalog.Projects)
	catalog.UpdatedAt = s.now().UTC()
	if err := writeProjectCatalogContext(ctx, s.catalogPath, s.masterKey, catalog); err != nil {
		cleanup()
		return err
	}
	created = false
	return syncDirectory(s.projectsDir)
}

func (s *Store) verifyMasterKey() error {
	return s.verifyMasterKeyContext(context.Background())
}

func (s *Store) verifyMasterKeyContext(ctx context.Context) error {
	current, err := loadExistingMasterKeyContext(ctx, s.keyPath)
	if errors.Is(err, ErrNotInitialized) {
		return integrity(0, "missing_master_key")
	}
	if err != nil {
		return err
	}
	defer zeroBytes(current)
	if len(current) != len(s.masterKey) || subtle.ConstantTimeCompare(current, s.masterKey) != 1 {
		return integrity(0, "master_key_changed")
	}
	return nil
}

func readProjectCatalog(path string, key []byte) (projectCatalog, error) {
	return readProjectCatalogContext(context.Background(), path, key)
}

func readProjectCatalogContext(ctx context.Context, path string, key []byte) (projectCatalog, error) {
	if err := contextError(ctx); err != nil {
		return projectCatalog{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return projectCatalog{}, integrity(0, "missing_project_catalog")
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return projectCatalog{}, integrity(0, "unsafe_project_catalog")
	}
	if err := inspectPrivateFilePermissionsContext(ctx, path); err != nil {
		return projectCatalog{}, integrity(0, "unsafe_project_catalog_permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return projectCatalog{}, fmt.Errorf("read project catalog: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return projectCatalog{}, err
	}
	var catalog projectCatalog
	if err := decodeStrictJSON(data, &catalog); err != nil {
		return projectCatalog{}, integrity(0, "invalid_project_catalog")
	}
	if catalog.Schema != projectCatalogSchemaV1 || catalog.Projects == nil || catalog.UpdatedAt.IsZero() || catalog.RecordMAC == "" {
		return projectCatalog{}, integrity(0, "invalid_project_catalog_fields")
	}
	previous := ""
	for _, id := range catalog.Projects {
		if !validProjectID(id) || (previous != "" && id <= previous) {
			return projectCatalog{}, integrity(0, "invalid_project_catalog_projects")
		}
		previous = id
	}
	expected, err := signJSONContext(ctx, key, "ward-audit-project-catalog/v1", catalogWithoutMAC(catalog))
	if err != nil {
		return projectCatalog{}, err
	}
	if !verifyHexMAC(expected, catalog.RecordMAC) {
		return projectCatalog{}, integrity(0, "project_catalog_mac_mismatch")
	}
	return catalog, nil
}

func writeProjectCatalog(path string, key []byte, catalog projectCatalog) error {
	return writeProjectCatalogContext(context.Background(), path, key, catalog)
}

func writeProjectCatalogContext(ctx context.Context, path string, key []byte, catalog projectCatalog) error {
	catalog.Schema = projectCatalogSchemaV1
	catalog.RecordMAC = ""
	mac, err := signJSONContext(ctx, key, "ward-audit-project-catalog/v1", catalog)
	if err != nil {
		return fmt.Errorf("sign project catalog: %w", err)
	}
	catalog.RecordMAC = mac
	if err := writePrivateJSONContext(ctx, filepath.Dir(path), path, catalog); err != nil {
		return fmt.Errorf("write project catalog: %w", err)
	}
	return nil
}

func validateCatalogLayout(projectsDir string, masterKey []byte, catalog projectCatalog) error {
	return validateCatalogLayoutContext(context.Background(), projectsDir, masterKey, catalog)
}

func validateCatalogLayoutContext(ctx context.Context, projectsDir string, masterKey []byte, catalog projectCatalog) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	actual, err := listProjectDirectoryIDsContext(ctx, projectsDir)
	if err != nil {
		return err
	}
	if len(actual) != len(catalog.Projects) {
		return integrity(0, "project_catalog_layout_mismatch")
	}
	for index, id := range catalog.Projects {
		if err := contextError(ctx); err != nil {
			return err
		}
		if actual[index] != id {
			return integrity(0, "project_catalog_layout_mismatch")
		}
		dir := filepath.Join(projectsDir, id)
		if err := inspectPrivateDirectoryContext(ctx, dir); err != nil {
			return integrity(0, "unsafe_project_directory")
		}
		if err := inspectProjectMarkerContext(ctx, filepath.Join(dir, projectMarkerFile), id, deriveProjectKey(masterKey, id)); err != nil {
			return err
		}
		if err := inspectPersistentLockContext(ctx, filepath.Join(dir, projectLockFile)); err != nil {
			return err
		}
	}
	return contextError(ctx)
}

func inspectProjectMarker(path, id string, key []byte) error {
	return inspectProjectMarkerContext(context.Background(), path, id, key)
}

func inspectProjectMarkerContext(ctx context.Context, path, id string, key []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return integrity(0, "unsafe_project_marker")
	}
	if err := inspectPrivateFilePermissionsContext(ctx, path); err != nil {
		return integrity(0, "unsafe_project_marker_permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return integrity(0, "missing_project_marker")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	var marker projectMarker
	if err := decodeStrictJSON(data, &marker); err != nil {
		return integrity(0, "invalid_project_marker")
	}
	if marker.Schema != projectMarkerSchemaV1 || marker.ProjectID != id || marker.CreatedAt.IsZero() || marker.RecordMAC == "" {
		return integrity(0, "invalid_project_marker_fields")
	}
	expected, err := signJSONContext(ctx, key, "ward-audit-project/v1", markerWithoutMAC(marker))
	if err != nil {
		return err
	}
	if !verifyHexMAC(expected, marker.RecordMAC) {
		return integrity(0, "project_marker_mac_mismatch")
	}
	return nil
}

func inspectPersistentLock(path string) error {
	return inspectPersistentLockContext(context.Background(), path)
}

func inspectPersistentLockContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return integrity(0, "missing_project_lock")
	}
	if err := inspectPrivateFilePermissionsContext(ctx, path); err != nil {
		return integrity(0, "unsafe_project_lock_permissions")
	}
	return nil
}

func listProjectDirectoryIDs(projectsDir string) ([]string, error) {
	return listProjectDirectoryIDsContext(context.Background(), projectsDir)
}

func listProjectDirectoryIDsContext(ctx context.Context, projectsDir string) ([]string, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(projectsDir)
	if err != nil {
		return nil, fmt.Errorf("list audit projects: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if !validProjectID(entry.Name()) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return nil, integrity(0, "unsafe_project_directory")
		}
		ids = append(ids, entry.Name())
	}
	sort.Strings(ids)
	return ids, nil
}

func validProjectID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func catalogHasProject(catalog projectCatalog, id string) bool {
	index := sort.SearchStrings(catalog.Projects, id)
	return index < len(catalog.Projects) && catalog.Projects[index] == id
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func writePrivateJSON(dir, path string, value any) error {
	return writePrivateJSONContext(context.Background(), dir, path, value)
}

func writePrivateJSONContext(ctx context.Context, dir, path string, value any) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".audit-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := securePrivateFileContext(ctx, temporaryPath); err != nil {
		cleanup()
		return err
	}
	if err := writeAndSyncContext(ctx, temporary, encoded); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := contextError(ctx); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := replaceFile(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	// The replacement is committed; do not report a context error after the
	// caller-visible state has changed.
	return syncDirectory(dir)
}
