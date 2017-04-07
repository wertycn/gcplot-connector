package com.gcplot.connector;

import com.beust.jcommander.IValueValidator;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static java.nio.file.StandardWatchEventKinds.*;

/**
 * @author <a href="mailto:art.dm.ser@gmail.com">Artem Dmitriev</a>
 *         3/28/17
 */
public class Bootstrap {
    private static final Logger LOG = LoggerFactory.getLogger(Bootstrap.class);
    private static final ObjectMapper JSON_FACTORY = new ObjectMapper();
    private static final String GET_ANALYZE = "/analyse/get";
    private static final String GET_ACCOUNT_ID = "/user/account/id";
    private static final String UPLOAD_DIR = "/upload";

    @Parameter(names = { "-logs_dir" }, required = true, validateValueWith = DirectoryValidator.class, description = "Directory where log files are located")
    private String logsDir;
    @Parameter(names = { "-gcp_host" }, required = true, validateValueWith = EmptyStringValidator.class, description = "GCPlot API host address")
    private String gcpHost;
    @Parameter(names = { "-data_dir" }, required = true, validateValueWith = DirectoryValidator.class, description = "Connector data directory")
    private String dataDir;
    @Parameter(names = { "-analyze_group" }, validateValueWith = EmptyStringValidator.class, required = true, description = "Analyze Group ID")
    private String analyzeId;
    @Parameter(names = { "-jvm_id" }, required = true, validateValueWith = EmptyStringValidator.class, description = "JVM ID")
    private String jvmId;
    @Parameter(names = { "-token" }, required = true, validateValueWith = EmptyStringValidator.class, description = "Token in GCPlot platform")
    private String token;
    @Parameter(names = { "-https" }, description = "Whether to use secure connections.")
    private boolean isHttps = true;
    @Parameter(names = { "-extension" }, description = "GC Log Files extension suffix (before .N number for rotating logs)")
    private String extension = ".log";
    @Parameter(names = { "-reaload_config_ms" }, description = "Config reload period in milliseconds.")
    private long reloadConfigMs = 30000;
    @Parameter(names = { "-sync_files_ms" }, description = "Log files sync period in milliseconds.")
    private long filesSyncMs = 5000;
    @Parameter(names = { "-ttl" })
    private long ttl = TimeUnit.DAYS.toMillis(14);
    @Parameter(names = { "-version" }, required = true)
    private String version;

    private CloseableHttpClient httpclient = HttpClients.createDefault();
    private ScheduledExecutorService configurationReloader = Executors.newSingleThreadScheduledExecutor();
    private ScheduledExecutorService conductorExecutor = Executors.newSingleThreadScheduledExecutor();
    private ScheduledExecutorService ttlExecutor = Executors.newSingleThreadScheduledExecutor();
    private ExecutorService listenerExecutor = Executors.newSingleThreadExecutor();
    private ExecutorService uploadExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);
    private JsonNode analyze;
    private volatile S3ResourceManager s3ResourceManager;

    public void run() throws Exception {
        try {
            String version = call("/connector/version/latest").get("result").asText("");
            if (!version.equals(this.version)) {
                LOG.warn("Latest GCPC version is {}, while you have {}. Please consider updating.", version, this.version);
            }
        } catch (Throwable ignored) {}
        if (!new File(dataDir + UPLOAD_DIR).exists()) {
            new File(dataDir + UPLOAD_DIR).mkdir();
        }
        loadAnalyze();
        configurationReloader.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                LOG.info("Reloading configuration started.");
                try {
                    loadAnalyze();
                } catch (Throwable t) {
                    LOG.error(t.getMessage(), t);
                } finally {
                    LOG.info("Reloading configuration completed.");
                }
            }
        }, reloadConfigMs, reloadConfigMs, TimeUnit.MILLISECONDS);
        listenerExecutor.submit(new Runnable() {
            @Override
            public void run() {
                LOG.info("Starting directory watcher daemon.");
                try {
                    WatchService watcher = FileSystems.getDefault().newWatchService();
                    Path dir = Paths.get(logsDir);
                    LOG.debug("Registering watcher on {}", dir);
                    dir.register(watcher, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);

                    while (true) {
                        WatchKey key = watcher.take();

                        for (WatchEvent<?> event : key.pollEvents()) {
                            WatchEvent.Kind<?> kind = event.kind();
                            if (kind == OVERFLOW || kind == ENTRY_DELETE) {
                                continue;
                            }
                            WatchEvent<Path> ev = (WatchEvent<Path>) event;
                            File f = ev.context().toFile();
                            LOG.debug("Directory Watcher: Received notify about '{}' with kind {}", f.getName(), kind.name());

                            try {
                                if (!extensionMatches(f)) {
                                    LOG.debug("Directory Watcher: Extension doesn't match for {}", f.getName());
                                }
                                syncFiles(f);
                            } catch (Throwable t) {
                                LOG.error(t.getMessage(), t);
                            }
                        }

                        boolean valid = key.reset();
                        if (!valid) {
                            break;
                        }
                    }
                } catch (Throwable t) {
                    LOG.error(t.getMessage(), t);
                } finally {
                    LOG.info("Stopping directory watcher daemon.");
                }
            }
        });
        conductorExecutor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                LOG.debug("Conductor process started.");
                try {
                    List<File> files =
                            new ArrayList<>(FileUtils.listFiles(new File(dataDir + UPLOAD_DIR), null, false));
                    for (final File f : files) {
                        LOG.debug("Conductor: Checking {}", f.getName());
                        try {
                            if (f.getName().endsWith(".progress")) {
                                continue;
                            }
                            final File inProgress = new File(f.getParent(), f.getName() + ".progress");
                            if (f.length() > 0 && !inProgress.exists()) {
                                inProgress.createNewFile();

                                uploadExecutor.submit(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            S3ResourceManager rm = s3ResourceManager;
                                            if (rm != null) {
                                                LOG.debug("Uploading {}", f.getName());
                                                rm.upload(f);
                                                zero(f);
                                            } else {
                                                LOG.debug("Not uploading {}", f.getName());
                                                zero(f);
                                            }
                                            FileUtils.deleteQuietly(inProgress);
                                        } catch (Throwable t) {
                                            LOG.error(t.getMessage(), t);
                                        }
                                    }
                                });
                            }
                        } catch (Throwable t) {
                            LOG.error(t.getMessage(), t);
                        }
                    }
                } catch (Throwable t) {
                    LOG.error(t.getMessage(), t);
                } finally {
                    LOG.debug("Conductor process finished.");
                }
            }
        }, filesSyncMs, filesSyncMs, TimeUnit.MILLISECONDS);
        ttlExecutor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                try {
                    LOG.debug("TTL process started.");
                    List<File> files =
                            new ArrayList<>(FileUtils.listFiles(new File(dataDir + UPLOAD_DIR), null, false));
                    for (File f : files) {
                        if (f.length() == 0 && !f.getName().endsWith(".progress")) {
                            long lm = f.lastModified();
                            if (lm > 0 && System.currentTimeMillis() - lm > ttl) {
                                LOG.debug("TTL: deleting {}", f);
                                FileUtils.deleteQuietly(f);
                            }
                        }
                    }
                } catch (Throwable t) {
                    LOG.error(t.getMessage(), t);
                } finally {
                    LOG.debug("TTL process finished.");
                }
            }
        }, 30, 30, TimeUnit.MINUTES);
    }

    private void checkAndScheduleForUpload(File f) {
        try {
            String hex;
            try (FileInputStream fis = new FileInputStream(f)) {
                if (isGzipped(f)) {
                    hex = DigestUtils.sha1Hex(new GZIPInputStream(fis));
                } else {
                    hex = DigestUtils.sha1Hex(fis);
                }
            }
            String fileName = hex + ".log.gz";
            File target = new File(dataDir + UPLOAD_DIR, fileName);
            if (!target.exists()) {
                LOG.debug("File Sync: Copying {} to {}", f.getName(), fileName);
                try (GZIPOutputStream gos = new GZIPOutputStream(new FileOutputStream(target))) {
                    if (isGzipped(f)) {
                        try (GZIPInputStream gzip = new GZIPInputStream(new FileInputStream(f))) {
                            IOUtils.copy(gzip, gos);
                        }
                    } else {
                        FileUtils.copyFile(f, gos);
                    }
                }
            } else {
                LOG.debug("File Sync: {} already exists.", fileName);
            }
        } catch (Throwable t) {
            LOG.error(t.getMessage(), t);
        }
    }

    private void syncFiles(File f) throws IOException {
        for (File file : new ArrayList<>(FileUtils.listFiles(new File(logsDir), null, false))) {
            if (!file.getName().equals(f.getName()) && extensionMatches(file)) {
                LOG.debug("Checking {} for possible sync.", file.getName());
                checkAndScheduleForUpload(file);
            }
        }
    }

    private boolean extensionMatches(File f) {
        return f.getName().contains(extension) &&
                (f.getName().endsWith(extension)
                        || f.getName().endsWith(extension + ".gz")
                        || f.getName().matches("^.*\\.\\d(\\.gz)?$"));
    }


    private boolean isGzipped(File f) {
        return f.getName().endsWith(".gz");
    }

    private void loadAnalyze() throws Exception {
        String accountId = call(GET_ACCOUNT_ID, Collections.<String, String>emptyMap()).asText();
        analyze = call(GET_ANALYZE, Collections.singletonMap("id", analyzeId));
        LOG.debug("Account - {}", accountId);
        LOG.debug("Analyze - {}", analyze);
        if (analyze.has("id")) {
            String sourceTypeStr = analyze.get("source_type").asText("");
            if (Strings.isNullOrEmpty(sourceTypeStr)) {
                LOG.error("Analyze Group - Source Type is empty.");
            } else {
                SourceType sourceType = SourceType.valueOf(sourceTypeStr.toUpperCase());
                Properties props = Utils.fromString(analyze.get("source_config").asText(""));

                if (sourceType == SourceType.NONE) {
                    LOG.info("Analyze Group {} has none Source Type set.", analyzeId);
                    s3ResourceManager = null;
                } else if (sourceType == SourceType.GCS) {
                    LOG.error("Source Type {} is not supported by this version. Consider updating.", sourceTypeStr);
                    s3ResourceManager = null;
                } else {
                    reloadResourceManager(accountId, sourceType, props);
                }
            }
        } else {
            LOG.error("Unknown Analyze Group response: {}", analyze);
        }
    }

    private void reloadResourceManager(String accountId, SourceType sourceType, Properties props) throws Exception {
        String basePath;
        S3Connector connector = new S3Connector();
        if (sourceType == SourceType.INTERNAL) {
            JsonNode internalSettings = call("/connector/internal/settings", Collections.<String, String>emptyMap());
            connector.setBucket(internalSettings.get("s3_bucket").asText());
            connector.setRegion(internalSettings.get("s3_region").asText());
            connector.setAccessKey(internalSettings.get("s3_access_key").asText());
            connector.setSecretKey(internalSettings.get("s3_secret_key").asText());
            basePath = normPath(internalSettings.get("s3_base_path").asText());
        } else if (sourceType == SourceType.S3) {
            connector.setBucket(props.getProperty("s3.bucket", ""));
            connector.setRegion(props.getProperty("s3.region.id", "us-east-1"));
            connector.setAccessKey(props.getProperty("s3.access_key", ""));
            connector.setSecretKey(props.getProperty("s3.secret_key", ""));
            basePath = normPath(props.getProperty("s3.prefix", ""));
        } else {
            throw new RuntimeException("Unknown Source Type = " + sourceType);
        }
        connector.init();
        this.s3ResourceManager = new S3ResourceManager(connector, basePath, accountId, analyzeId, jvmId);
    }

    private String normPath(String basePath) {
        if (!Strings.isNullOrEmpty(basePath)) {
            if (!basePath.endsWith("/")) {
                basePath += '/';
            }
            while (basePath.startsWith("/")) {
                basePath = basePath.substring(1);
            }
        }
        return Strings.nullToEmpty(basePath);
    }

    public JsonNode call(String path) throws Exception {
        return call(path, Collections.<String, String>emptyMap());
    }

    public JsonNode call(String path, Map<String, String> params) throws Exception {
        URIBuilder builder = new URIBuilder()
                .setScheme(isHttps ? "https" : "http")
                .setHost(gcpHost)
                .setPath(path)
                .setParameter("token", token);
        for (Map.Entry<String, String> i : params.entrySet()) {
            builder.addParameter(i.getKey(), i.getValue());
        }
        HttpGet get = new HttpGet(builder.build());
        LOG.debug("Calling {}", get);
        CloseableHttpResponse resp = httpclient.execute(get);
        return JSON_FACTORY.readTree(resp.getEntity().getContent()).get("result");
    }

    private void zero(File file) {
        try {
            LOG.debug("Zeroing {}", file.getName());
            Files.newOutputStream(file.toPath(), StandardOpenOption.TRUNCATE_EXISTING).close();
        } catch (IOException ignored) {
        }
    }

    public static void main(String[] args) {
        try {
            LOG.info("Starting GCPlot connector.");
            LOG.info("Using Java Version {} by {}, {} {} {}", System.getProperty("java.version"),
                    System.getProperty("java.vendor"), System.getProperty("os.arch"),
                    System.getProperty("os.name"), System.getProperty("os.version"));

            Bootstrap bootstrap = new Bootstrap();
            new JCommander(bootstrap, args);
            bootstrap.run();
            Thread.sleep(Long.MAX_VALUE);
        } catch (Throwable t) {
            LOG.error(t.getMessage(), t);
        }
    }


    public static class EmptyStringValidator implements IValueValidator<String> {
        @Override
        public void validate(String name, String value) throws ParameterException {
            if (Strings.isNullOrEmpty(value)) {
                throw new ParameterException("Value is empty.");
            }
        }
    }

    public static class DirectoryValidator implements IValueValidator<String> {
        @Override
        public void validate(String name, String value) throws ParameterException {
            if (Strings.isNullOrEmpty(value)) {
                throw new ParameterException("Value is empty.");
            }
            if (!new File(value).exists()) {
                throw new ParameterException("Directory does not exist - " + value);
            }
        }
    }

}
