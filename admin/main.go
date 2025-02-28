package main

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/handlers"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/cache"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/version"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
)

// Constants for the service
const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceAdmin
	// Service version
	serviceVersion string = version.OsctrlVersion
	// Service description
	serviceDescription string = "Admin service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 7
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 7
)

// Paths
const (
	// Default endpoint to handle HTTP health
	healthPath string = "/health"
	// Default endpoint to handle Login
	loginPath string = "/login"
	// Default endpoint to handle Logout
	logoutPath string = "/logout"
	// Default endpoint to handle HTTP(500) errors
	errorPath string = "/error"
	// Default endpoint to handle Forbidden(403) errors
	forbiddenPath string = "/forbidden"
	// Default endpoint for favicon
	faviconPath string = "/favicon.ico"
)

// Configuration
const (
	// Default SAML configuration file
	defSAMLConfigurationFile string = "config/saml.json"
	// Default JWT configuration file
	defJWTConfigurationFile string = "config/jwt.json"
	// Default service configuration file
	defConfigurationFile string = "config/" + settings.ServiceAdmin + ".json"
	// Default DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Default redis configuration file
	defRedisConfigurationFile string = "config/redis.json"
	// Default Logger configuration file
	defLoggerConfigurationFile string = "config/logger.json"
	// Default TLS certificate file
	defTLSCertificateFile string = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile string = "config/tls.key"
	// Default carver configuration file
	defCarverConfigurationFile string = "config/carver.json"
)

// Random
const (
	// Static files folder
	defStaticFilesFolder string = "./static"
	// Default templates folder
	defTemplatesFolder string = "./tmpl_admin"
	// Default carved files folder
	defCarvedFolder string = "./carved_files/"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default hours to classify nodes as inactive
	defaultInactive int = -72
)

// osquery
const (
	// osquery version to display tables
	defOsqueryTablesVersion = version.OsqueryVersion
	// JSON file with osquery tables data
	defOsqueryTablesFile string = "data/" + defOsqueryTablesVersion + ".json"
)

// Global general variables
var (
	err               error
	adminConfigValues types.JSONConfigurationAdmin
	adminConfig       types.JSONConfigurationAdmin
	s3LogConfig       types.S3Configuration
	s3CarverConfig    types.S3Configuration
	dbConfigValues    backend.JSONConfigurationDB
	dbConfig          backend.JSONConfigurationDB
	redisConfigValues cache.JSONConfigurationRedis
	redisConfig       cache.JSONConfigurationRedis
	db                *backend.DBManager
	redis             *cache.RedisManager
	settingsmgr       *settings.Settings
	nodesmgr          *nodes.NodeManager
	queriesmgr        *queries.Queries
	carvesmgr         *carves.Carves
	sessionsmgr       *sessions.SessionManager
	envs              *environments.Environment
	adminUsers        *users.UserManager
	tagsmgr           *tags.TagManager
	carvers3          *carves.CarverS3
	app               *cli.App
	flags             []cli.Flag
	// FIXME this is nasty and should not be a global but here we are
	osqueryTables []types.OsqueryTable
	adminMetrics  *metrics.Metrics
	handlersAdmin *handlers.HandlersAdmin
)

// Variables for flags
var (
	configFlag           bool
	dbFlag               bool
	redisFlag            bool
	serviceConfigFile    string
	dbConfigFile         string
	redisConfigFile      string
	tlsServer            bool
	tlsCertFile          string
	tlsKeyFile           string
	samlConfigFile       string
	jwtFlag              bool
	jwtConfigFile        string
	osqueryTablesFile    string
	osqueryTablesVersion string
	loggerFile           string
	staticFilesFolder    string
	staticOffline        bool
	carvedFilesFolder    string
	templatesFolder      string
	carverConfigFile     string
)

// SAML variables
var (
	samlMiddleware *samlsp.Middleware
	samlConfig     JSONConfigurationSAML
	samlData       samlThings
)

// JWT variables
var (
	jwtConfigValues types.JSONConfigurationJWT
	jwtConfig       types.JSONConfigurationJWT
)

// Valid values for auth in configuration
var validAuth = map[string]bool{
	settings.AuthDB:   true,
	settings.AuthSAML: true,
	settings.AuthJSON: true,
}

// Valid values for carver in configuration
var validCarver = map[string]bool{
	settings.CarverDB:    true,
	settings.CarverLocal: true,
	settings.CarverS3:    true,
}

// Function to load the configuration file
func loadConfiguration(file, service string) (types.JSONConfigurationAdmin, error) {
	var cfg types.JSONConfigurationAdmin
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// Admin values
	adminRaw := viper.Sub(service)
	if adminRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", service, file)
	}
	if err := adminRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method")
	}
	if !validCarver[cfg.Carver] {
		return cfg, fmt.Errorf("Invalid carver method")
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
		&cli.BoolFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       false,
			Usage:       "Provide service configuration via JSON file",
			EnvVars:     []string{"SERVICE_CONFIG"},
			Destination: &configFlag,
		},
		&cli.StringFlag{
			Name:        "config-file",
			Aliases:     []string{"C"},
			Value:       defConfigurationFile,
			Usage:       "Load service configuration from `FILE`",
			EnvVars:     []string{"SERVICE_CONFIG_FILE"},
			Destination: &serviceConfigFile,
		},
		&cli.StringFlag{
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "0.0.0.0",
			Usage:       "Listener for the service",
			EnvVars:     []string{"SERVICE_LISTENER"},
			Destination: &adminConfigValues.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9001",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &adminConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       settings.AuthDB,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &adminConfigValues.Auth,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &adminConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "session-key",
			Value:       "",
			Usage:       "Session key to generate cookies from it",
			EnvVars:     []string{"SESSION_KEY"},
			Destination: &adminConfigValues.SessionKey,
		},
		&cli.StringFlag{
			Name:        "logging",
			Aliases:     []string{"L"},
			Value:       settings.LoggingDB,
			Usage:       "Logging mechanism to handle logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGER"},
			Destination: &adminConfigValues.Logger,
		},
		&cli.BoolFlag{
			Name:        "redis",
			Aliases:     []string{"r"},
			Value:       false,
			Usage:       "Provide redis configuration via JSON file",
			EnvVars:     []string{"REDIS_CONFIG"},
			Destination: &redisFlag,
		},
		&cli.StringFlag{
			Name:        "redis-file",
			Aliases:     []string{"R"},
			Value:       defRedisConfigurationFile,
			Usage:       "Load redis configuration from `FILE`",
			EnvVars:     []string{"REDIS_CONFIG_FILE"},
			Destination: &redisConfigFile,
		},
		&cli.StringFlag{
			Name:        "redis-connection-string",
			Value:       "",
			Usage:       "Redis connection string, must include schema (<redis|rediss|unix>://<user>:<pass>@<host>:<port>/<db>?<options>",
			EnvVars:     []string{"REDIS_CONNECTION_STRING"},
			Destination: &redisConfigValues.ConnectionString,
		},
		&cli.StringFlag{
			Name:        "redis-host",
			Value:       "127.0.0.1",
			Usage:       "Redis host to be connected to",
			EnvVars:     []string{"REDIS_HOST"},
			Destination: &redisConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "redis-port",
			Value:       "6379",
			Usage:       "Redis port to be connected to",
			EnvVars:     []string{"REDIS_PORT"},
			Destination: &redisConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "redis-pass",
			Value:       "",
			Usage:       "Password to be used for redis",
			EnvVars:     []string{"REDIS_PASS"},
			Destination: &redisConfigValues.Password,
		},
		&cli.IntFlag{
			Name:        "redis-db",
			Value:       0,
			Usage:       "Redis database to be selected after connecting",
			EnvVars:     []string{"REDIS_DB"},
			Destination: &redisConfigValues.DB,
		},
		&cli.IntFlag{
			Name:        "redis-status-exp",
			Value:       cache.StatusExpiration,
			Usage:       "Redis expiration in hours for status logs",
			EnvVars:     []string{"REDIS_STATUS_EXP"},
			Destination: &redisConfigValues.StatusExpirationHours,
		},
		&cli.IntFlag{
			Name:        "redis-result-exp",
			Value:       cache.ResultExpiration,
			Usage:       "Redis expiration in hours for result logs",
			EnvVars:     []string{"REDIS_RESULT_EXP"},
			Destination: &redisConfigValues.ResultExpirationHours,
		},
		&cli.IntFlag{
			Name:        "redis-query-exp",
			Value:       cache.QueryExpiration,
			Usage:       "Redis expiration in hours for query logs",
			EnvVars:     []string{"REDIS_QUERY_EXP"},
			Destination: &redisConfigValues.QueryExpirationHours,
		},
		&cli.IntFlag{
			Name:        "redis-conn-retry",
			Value:       defaultRedisRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the cache, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"REDIS_CONN_RETRY"},
			Destination: &redisConfigValues.ConnRetry,
		},
		&cli.BoolFlag{
			Name:        "db",
			Aliases:     []string{"d"},
			Value:       false,
			Usage:       "Provide DB configuration via JSON file",
			EnvVars:     []string{"DB_CONFIG"},
			Destination: &dbFlag,
		},
		&cli.StringFlag{
			Name:        "db-file",
			Aliases:     []string{"D"},
			Value:       defDBConfigurationFile,
			Usage:       "Load DB configuration from `FILE`",
			EnvVars:     []string{"DB_CONFIG_FILE"},
			Destination: &dbConfigFile,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			EnvVars:     []string{"DB_HOST"},
			Destination: &dbConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_PORT"},
			Destination: &dbConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "osctrl",
			Usage:       "Database name to be used in the backend",
			EnvVars:     []string{"DB_NAME"},
			Destination: &dbConfigValues.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			EnvVars:     []string{"DB_USER"},
			Destination: &dbConfigValues.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"DB_PASS"},
			Destination: &dbConfigValues.Password,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			EnvVars:     []string{"DB_MAX_IDLE_CONNS"},
			Destination: &dbConfigValues.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			EnvVars:     []string{"DB_MAX_OPEN_CONNS"},
			Destination: &dbConfigValues.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			EnvVars:     []string{"DB_CONN_MAX_LIFETIME"},
			Destination: &dbConfigValues.ConnMaxLifetime,
		},
		&cli.IntFlag{
			Name:        "db-conn-retry",
			Value:       defaultBackendRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the database, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"DB_CONN_RETRY"},
			Destination: &dbConfigValues.ConnRetry,
		},
		&cli.BoolFlag{
			Name:        "tls",
			Aliases:     []string{"t"},
			Value:       false,
			Usage:       "Enable TLS termination. It requires certificate and key",
			EnvVars:     []string{"TLS_SERVER"},
			Destination: &tlsServer,
		},
		&cli.StringFlag{
			Name:        "cert",
			Aliases:     []string{"T"},
			Value:       defTLSCertificateFile,
			Usage:       "TLS termination certificate from `FILE`",
			EnvVars:     []string{"TLS_CERTIFICATE"},
			Destination: &tlsCertFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Aliases:     []string{"K"},
			Value:       defTLSKeyFile,
			Usage:       "TLS termination private key from `FILE`",
			EnvVars:     []string{"TLS_KEY"},
			Destination: &tlsKeyFile,
		},
		&cli.StringFlag{
			Name:        "saml-file",
			Value:       defSAMLConfigurationFile,
			Usage:       "Load SAML configuration from `FILE`",
			EnvVars:     []string{"SAML_CONFIG_FILE"},
			Destination: &samlConfigFile,
		},
		&cli.BoolFlag{
			Name:        "jwt",
			Aliases:     []string{"j"},
			Value:       false,
			Usage:       "Provide JWT configuration via JSON file",
			EnvVars:     []string{"JWT_CONFIG"},
			Destination: &jwtFlag,
		},
		&cli.StringFlag{
			Name:        "jwt-file",
			Value:       defJWTConfigurationFile,
			Usage:       "Load JWT configuration from `FILE`",
			EnvVars:     []string{"JWT_CONFIG_FILE"},
			Destination: &jwtConfigFile,
		},
		&cli.StringFlag{
			Name:        "jwt-secret",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"JWT_SECRET"},
			Destination: &jwtConfigValues.JWTSecret,
		},
		&cli.IntFlag{
			Name:        "jwt-expire",
			Value:       3,
			Usage:       "Maximum amount of hours for the tokens to expire",
			EnvVars:     []string{"JWT_EXPIRE"},
			Destination: &jwtConfigValues.HoursToExpire,
		},
		&cli.StringFlag{
			Name:        "osquery-version",
			Value:       defOsqueryTablesVersion,
			Usage:       "Set osquery version as default to be used",
			EnvVars:     []string{"OSQUERY_VERSION"},
			Destination: &osqueryTablesVersion,
		},
		&cli.StringFlag{
			Name:        "osquery-tables",
			Value:       defOsqueryTablesFile,
			Usage:       "Load osquery tables schema from `FILE`",
			EnvVars:     []string{"OSQUERY_TABLES"},
			Destination: &osqueryTablesFile,
		},
		&cli.StringFlag{
			Name:        "logger-file",
			Aliases:     []string{"F"},
			Value:       defLoggerConfigurationFile,
			Usage:       "Logger configuration to handle status/results logs from nodes",
			EnvVars:     []string{"LOGGER_FILE"},
			Destination: &loggerFile,
		},
		&cli.StringFlag{
			Name:        "static",
			Aliases:     []string{"s"},
			Value:       defStaticFilesFolder,
			Usage:       "Directory with all the static files needed for the osctrl-admin UI",
			EnvVars:     []string{"STATIC_FILES"},
			Destination: &staticFilesFolder,
		},
		&cli.BoolFlag{
			Name:        "static-offline",
			Aliases:     []string{"S"},
			Value:       false,
			Usage:       "Use offline static files (js and css). Default is online files.",
			EnvVars:     []string{"STATIC_ONLINE"},
			Destination: &staticOffline,
		},
		&cli.StringFlag{
			Name:        "templates",
			Value:       defTemplatesFolder,
			Usage:       "Directory with all the templates needed for the osctrl-admin UI",
			EnvVars:     []string{"STATIC_FILES"},
			Destination: &templatesFolder,
		},
		&cli.StringFlag{
			Name:        "carved",
			Value:       defCarvedFolder,
			Usage:       "Directory for all the received carved files from osquery",
			EnvVars:     []string{"CARVED_FILES"},
			Destination: &carvedFilesFolder,
		},
		&cli.StringFlag{
			Name:        "carver-type",
			Value:       settings.CarverDB,
			Usage:       "Carver to be used to receive files extracted from nodes",
			EnvVars:     []string{"CARVER_TYPE"},
			Destination: &adminConfig.Carver,
		},
		&cli.StringFlag{
			Name:        "carver-file",
			Value:       defCarverConfigurationFile,
			Usage:       "Carver configuration file to receive files extracted from nodes",
			EnvVars:     []string{"CARVER_FILE"},
			Destination: &carverConfigFile,
		},
		&cli.StringFlag{
			Name:        "log-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_BUCKET"},
			Destination: &s3LogConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "log-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_REGION"},
			Destination: &s3LogConfig.Region,
		},
		&cli.StringFlag{
			Name:        "log-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_KEY_ID"},
			Destination: &s3LogConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "log-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_SECRET"},
			Destination: &s3LogConfig.SecretAccessKey,
		},
		&cli.StringFlag{
			Name:        "carver-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_BUCKET"},
			Destination: &s3CarverConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "carver-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_REGION"},
			Destination: &s3CarverConfig.Region,
		},
		&cli.StringFlag{
			Name:        "carve-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_KEY_ID"},
			Destination: &s3CarverConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "carve-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_SECRET"},
			Destination: &s3CarverConfig.SecretAccessKey,
		},
	}
	// Logging format flags
	log.SetFlags(log.Lshortfile)
}

// Go go!
func osctrlAdminService() {
	// ////////////////////////////// Backend
	log.Println("Initializing backend...")
	for {
		db, err = backend.CreateDBManager(dbConfig)
		if db != nil {
			log.Println("Connection to backend successful!")
			break
		}
		if err != nil {
			log.Printf("Failed to connect to backend - %v", err)
			if dbConfig.ConnRetry == 0 {
				log.Fatalf("Connection to backend failed and no retry was set")
			}
		}
		log.Printf("Backend NOT ready! Retrying in %d seconds...\n", dbConfig.ConnRetry)
		time.Sleep(time.Duration(dbConfig.ConnRetry) * time.Second)
	}
	// ////////////////////////////// Cache
	log.Println("Initializing cache...")
	for {
		redis, err = cache.CreateRedisManager(redisConfig)
		if redis != nil {
			log.Println("Connection to cache successful!")
			break
		}
		if err != nil {
			log.Printf("Failed to connect to cache - %v", err)
			if redisConfig.ConnRetry == 0 {
				log.Fatalf("Connection to cache failed and no retry was set")
			}
		}
		log.Printf("Cache NOT ready! Retrying in %d seconds...\n", redisConfig.ConnRetry)
		time.Sleep(time.Duration(redisConfig.ConnRetry) * time.Second)
	}
	log.Println("Initialize users")
	adminUsers = users.CreateUserManager(db.Conn, &jwtConfig)
	log.Println("Initialize tags")
	tagsmgr = tags.CreateTagManager(db.Conn)
	log.Println("Initialize environments")
	envs = environments.CreateEnvironment(db.Conn)
	log.Println("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Println("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn)
	log.Println("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	log.Println("Initialize carves")
	carvesmgr = carves.CreateFileCarves(db.Conn, adminConfig.Carver, carvers3)
	log.Println("Initialize sessions")
	sessionsmgr = sessions.CreateSessionManager(db.Conn, authCookieName, adminConfig.SessionKey)
	log.Println("Loading service settings")
	if err := loadingSettings(settingsmgr); err != nil {
		log.Fatalf("Error loading settings - %v", err)
	}
	log.Println("Loading service metrics")
	adminMetrics, err = loadingMetrics(settingsmgr)
	if err != nil {
		log.Fatalf("Error loading metrics - %v", err)
	}

	// Start SAML Middleware if we are using SAML
	if adminConfig.Auth == settings.AuthSAML {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: SAML keypair")
		}
		// Initialize SAML keypair to sign SAML Request.
		var err error
		samlData, err = keypairSAML(samlConfig)
		if err != nil {
			log.Fatalf("Can not initialize SAML keypair %s", err)
		}
		samlMiddleware, err = samlsp.New(samlsp.Options{
			URL:               *samlData.RootURL,
			Key:               samlData.KeyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       samlData.KeyPair.Leaf,
			IDPMetadata:       samlData.IdpMetadata,
			AllowIDPInitiated: true,
		})
		if err != nil {
			log.Fatalf("Can not initialize SAML Middleware %s", err)
		}
	}

	// FIXME Redis cache - Ticker to cleanup sessions
	// FIXME splay this?
	go func() {
		_t := settingsmgr.CleanupSessions()
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Println("DebugService: Cleaning up sessions")
			}
			sessionsmgr.Cleanup()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()

	// Set the logger configuration file to empty if we are logging to anything but the DB
	if adminConfig.Logger != settings.LoggingDB {
		loggerFile = ""
	}

	// Initialize Admin handlers before router
	handlersAdmin = handlers.CreateHandlersAdmin(
		handlers.WithDB(db.Conn),
		handlers.WithEnvs(envs),
		handlers.WithUsers(adminUsers),
		handlers.WithTags(tagsmgr),
		handlers.WithNodes(nodesmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithCarves(carvesmgr),
		handlers.WithSettings(settingsmgr),
		handlers.WithMetrics(adminMetrics),
		handlers.WithCache(redis),
		handlers.WithSessions(sessionsmgr),
		handlers.WithVersion(serviceVersion),
		handlers.WithOsqueryVersion(osqueryTablesVersion),
		handlers.WithTemplates(templatesFolder),
		handlers.WithStaticLocation(staticOffline),
		handlers.WithOsqueryTables(osqueryTables),
		handlers.WithCarvesFolder(carvedFilesFolder),
		handlers.WithAdminConfig(&adminConfig),
		handlers.WithDBLogger(loggerFile),
	)

	// ////////////////////////// ADMIN
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Creating router")
	}
	// Create router for admin
	routerAdmin := mux.NewRouter()

	// ///////////////////////// UNAUTHENTICATED CONTENT
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Unauthenticated content")
	}
	// Admin: login only if local auth is enabled
	if adminConfig.Auth != settings.AuthNone && adminConfig.Auth != settings.AuthSAML {
		// login
		routerAdmin.HandleFunc(loginPath, handlersAdmin.LoginHandler).Methods("GET")
		routerAdmin.HandleFunc(loginPath, handlersAdmin.LoginPOSTHandler).Methods("POST")
		routerAdmin.HandleFunc(logoutPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loginPath, http.StatusFound)
		}).Methods("GET")
	}
	// Admin: health of service
	routerAdmin.HandleFunc(healthPath, handlersAdmin.HealthHandler).Methods("GET")
	// Admin: error
	routerAdmin.HandleFunc(errorPath, handlersAdmin.ErrorHandler).Methods("GET")
	// Admin: forbidden
	routerAdmin.HandleFunc(forbiddenPath, handlersAdmin.ForbiddenHandler).Methods("GET")
	// Admin: favicon
	routerAdmin.HandleFunc(faviconPath, handlersAdmin.FaviconHandler)
	// Admin: static
	routerAdmin.PathPrefix("/static/").Handler(
		http.StripPrefix("/static", http.FileServer(http.Dir(staticFilesFolder))))

	// ///////////////////////// AUTHENTICATED CONTENT
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Authenticated content")
	}
	// Admin: JSON data for environments
	routerAdmin.Handle("/json/environment/{env}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONEnvironmentHandler))).Methods("GET")
	// Admin: JSON data for platforms
	routerAdmin.Handle("/json/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONPlatformHandler))).Methods("GET")
	// Admin: JSON data for logs
	routerAdmin.Handle("/json/logs/{type}/{env}/{uuid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONLogsHandler))).Methods("GET")
	// Admin: JSON data for query logs
	routerAdmin.Handle("/json/query/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryLogsHandler))).Methods("GET")
	// Admin: JSON data for sidebar stats
	routerAdmin.Handle("/json/stats/{target}/{identifier}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONStatsHandler))).Methods("GET")
	// Admin: JSON data for tags
	routerAdmin.Handle("/json/tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONTagsHandler))).Methods("GET")
	// Admin: table for environments
	routerAdmin.Handle("/environment/{env}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvironmentHandler))).Methods("GET")
	// Admin: table for platforms
	routerAdmin.Handle("/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PlatformHandler))).Methods("GET")
	// Admin: root
	routerAdmin.Handle("/", handlerAuthCheck(http.HandlerFunc(handlersAdmin.RootHandler))).Methods("GET")
	// Admin: node view
	routerAdmin.Handle("/node/{uuid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeHandler))).Methods("GET")
	// Admin: multi node action
	routerAdmin.Handle("/node/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeActionsPOSTHandler))).Methods("POST")
	// Admin: run queries
	routerAdmin.Handle("/query/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunGETHandler))).Methods("GET")
	routerAdmin.Handle("/query/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunPOSTHandler))).Methods("POST")
	// Admin: list queries
	routerAdmin.Handle("/query/{env}/list", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryListGETHandler))).Methods("GET")
	// Admin: saved queries
	routerAdmin.Handle("/query/{env}/saved", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SavedQueriesGETHandler))).Methods("GET")
	// Admin: query actions
	routerAdmin.Handle("/query/{env}/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryActionsPOSTHandler))).Methods("POST")
	// Admin: query JSON
	routerAdmin.Handle("/query/{env}/json/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryHandler))).Methods("GET")
	// Admin: query logs
	routerAdmin.Handle("/query/{env}/logs/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryLogsHandler))).Methods("GET")
	// Admin: carve files
	routerAdmin.Handle("/carves/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunGETHandler))).Methods("GET")
	routerAdmin.Handle("/carves/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunPOSTHandler))).Methods("POST")
	// Admin: list carves
	routerAdmin.Handle("/carves/{env}/list", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesListGETHandler))).Methods("GET")
	// Admin: carves actions
	routerAdmin.Handle("/carves/{env}/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesActionsPOSTHandler))).Methods("POST")
	// Admin: carves JSON
	routerAdmin.Handle("/carves/{env}/json/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONCarvesHandler))).Methods("GET")
	// Admin: carves details
	routerAdmin.Handle("/carves/{env}/details/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDetailsHandler))).Methods("GET")
	// Admin: carves download
	routerAdmin.Handle("/carves/{env}/download/{sessionid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDownloadHandler))).Methods("GET")
	// Admin: nodes configuration
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfGETHandler))).Methods("GET")
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/intervals/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.IntervalsPOSTHandler))).Methods("POST")
	// Admin: nodes enroll
	routerAdmin.Handle("/enroll/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollGETHandler))).Methods("GET")
	routerAdmin.Handle("/enroll/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/expiration/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ExpirationPOSTHandler))).Methods("POST")
	// Admin: server settings
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsGETHandler))).Methods("GET")
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsPOSTHandler))).Methods("POST")
	// Admin: manage environments
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsGETHandler))).Methods("GET")
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsPOSTHandler))).Methods("POST")
	// Admin: manage users
	routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersGETHandler))).Methods("GET")
	routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsGETHandler))).Methods("GET")
	routerAdmin.Handle("/users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsPOSTHandler))).Methods("POST")
	// Admin: manage tags
	routerAdmin.Handle("/tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsGETHandler))).Methods("GET")
	routerAdmin.Handle("/tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/tags/nodes", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagNodesPOSTHandler))).Methods("POST")
	// Admin: manage tokens
	routerAdmin.Handle("/tokens/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensGETHandler))).Methods("GET")
	routerAdmin.Handle("/tokens/{username}/refresh", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensPOSTHandler))).Methods("POST")
	// Admin: edit profile
	routerAdmin.Handle("/profile", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfileGETHandler))).Methods("GET")
	routerAdmin.Handle("/profile", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfilePOSTHandler))).Methods("POST")
	// Admin: dashboard and search bar
	routerAdmin.Handle("/dashboard", handlerAuthCheck(http.HandlerFunc(handlersAdmin.DashboardGETHandler))).Methods("GET")
	// Admin: logout
	routerAdmin.Handle(logoutPath, handlerAuthCheck(http.HandlerFunc(handlersAdmin.LogoutPOSTHandler))).Methods("POST")
	// SAML ACS
	if adminConfig.Auth == settings.AuthSAML {
		routerAdmin.PathPrefix("/saml/").Handler(samlMiddleware)
		routerAdmin.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
		}).Methods("GET")
		routerAdmin.HandleFunc(logoutPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, samlConfig.LogoutURL, http.StatusFound)
		}).Methods("GET")
	}
	// Launch HTTP server for admin
	serviceAdmin := adminConfig.Listener + ":" + adminConfig.Port
	if tlsServer {
		cfg := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
		srv := &http.Server{
			Addr:         serviceAdmin,
			Handler:      routerAdmin,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Printf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceAdmin)
		log.Fatal(srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
	} else {
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceAdmin)
		log.Fatal(http.ListenAndServe(serviceAdmin, routerAdmin))
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(c *cli.Context) error {
	// Load configuration if external JSON config file is used
	if configFlag {
		adminConfig, err = loadConfiguration(serviceConfigFile, settings.ServiceAdmin)
		if err != nil {
			return fmt.Errorf("Failed to load service configuration %s - %s", serviceConfigFile, err)
		}
	} else {
		adminConfig = adminConfigValues
	}
	// Load redis configuration if external JSON config file is used
	if redisFlag {
		redisConfig, err = cache.LoadConfiguration(redisConfigFile, cache.RedisKey)
		if err != nil {
			return fmt.Errorf("Failed to load redis configuration - %v", err)
		}
	} else {
		redisConfig = redisConfigValues
	}
	// Load DB configuration if external JSON config file is used
	if dbFlag {
		dbConfig, err = backend.LoadConfiguration(dbConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("Failed to load DB configuration - %v", err)
		}
	} else {
		dbConfig = dbConfigValues
	}
	// Load SAML configuration if this authentication is used in the service config
	if adminConfig.Auth == settings.AuthSAML {
		samlConfig, err = loadSAML(samlConfigFile)
		if err != nil {
			return fmt.Errorf("Failed to load SAML configuration - %v", err)
		}
	}
	// Load JWT configuration if external JWT JSON config file is used
	if jwtFlag {
		jwtConfig, err = loadJWTConfiguration(jwtConfigFile)
		if err != nil {
			return fmt.Errorf("Failed to load JWT configuration - %v", err)
		}
	} else {
		jwtConfig = jwtConfigValues
	}
	// Load osquery tables JSON file
	osqueryTables, err = loadOsqueryTables(osqueryTablesFile)
	if err != nil {
		return fmt.Errorf("Failed to load osquery tables - %v", err)
	}
	// Load carver configuration if external JSON config file is used
	if adminConfig.Carver == settings.CarverS3 {
		if s3CarverConfig.Bucket != "" {
			carvers3, err = carves.CreateCarverS3(s3CarverConfig)
		} else {
			carvers3, err = carves.CreateCarverS3File(carverConfigFile)
		}
		if err != nil {
			return fmt.Errorf("Failed to initiate s3 carver - %v", err)
		}
	}
	return nil
}

func main() {
	// Initiate CLI and parse arguments
	app = cli.NewApp()
	app.Name = serviceName
	app.Usage = appDescription
	app.Version = serviceVersion
	app.Description = appDescription
	app.Flags = flags
	// Define this command for help to exit when help flag is passed
	app.Commands = []*cli.Command{
		{
			Name: "help",
			Action: func(c *cli.Context) error {
				cli.ShowAppHelpAndExit(c, 0)
				return nil
			},
		},
	}
	app.Action = cliAction
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	// Service starts!
	osctrlAdminService()
}
