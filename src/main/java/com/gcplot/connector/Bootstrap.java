package com.gcplot.connector;

import com.beust.jcommander.IValueValidator;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.vfs2.*;
import org.apache.commons.vfs2.impl.DefaultFileMonitor;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * @author <a href="mailto:art.dm.ser@gmail.com">Artem Dmitriev</a>
 *         3/28/17
 */
public class Bootstrap {
    private static final Logger LOG = LoggerFactory.getLogger(Bootstrap.class);
    private static final ObjectMapper JSON_FACTORY = new ObjectMapper();
    private static final String ROLL_LOG_EXTENSION_PATTERN = "^.*\\.\\d+(\\.gz)?$";
    private static final String TIMESTAMP_PATTERN = "^( |\\t)*(\\d+\\.\\d+)\\:( |\\t)*";
    private static final int TIMESTAMP_FIND_LIMIT = 100;
    private static final String GET_ANALYZE = "/analyse/get";
    private static final String GET_ACCOUNT_ID = "/user/account/id";
    private static final String UPLOAD_DIR = "/upload";

    @Parameter(names = { "-logs_dirs" }, required = true, description = "Directory where log files are located")
    private String logsDirsStr;
    @Parameter(names = { "-gcp_host" }, required = true, validateValueWith = EmptyStringValidator.class, description = "GCPlot API host address")
    private String gcpHost;
    @Parameter(names = { "-data_dir" }, required = true, validateValueWith = DirectoryValidator.class, description = "Connector data directory")
    private String dataDir;
    @Parameter(names = { "-analyze_group" }, validateValueWith = EmptyStringValidator.class, required = true, description = "Analyze Group ID")
    private String analyzeId;
    @Parameter(names = { "-jvm_ids" }, required = true, validateValueWith = EmptyStringValidator.class, description = "JVM ID")
    private String jvmIdsStr;
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
    private ExecutorService listenerExecutor;
    private ExecutorService uploadExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);
    private Cache<String, Long> lastModifiedCache = CacheBuilder.newBuilder().maximumSize(10000).build();
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
        final List<String> jvmIds = Splitter.on(",").splitToList(jvmIdsStr);
        final List<String> logsDirs = Splitter.on(",").splitToList(logsDirsStr);
        if (logsDirs.size() < jvmIds.size()) {
            throw new IllegalArgumentException(String.format("JVM ids [%s] and Logs Dirs [%s] mismatch! Aborting.",
                    jvmIdsStr, logsDirsStr));
        }
        listenerExecutor = Executors.newFixedThreadPool(jvmIds.size());
        configurationReloader.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                LOG.debug("Reloading configuration started.");
                try {
                    loadAnalyze();
                } catch (Throwable t) {
                    LOG.error(t.getMessage(), t);
                } finally {
                    LOG.debug("Reloading configuration completed.");
                }
            }
        }, reloadConfigMs, reloadConfigMs, TimeUnit.MILLISECONDS);
        for (int i = 0; i < jvmIds.size(); i++) {
            final String jvmId = jvmIds.get(i);
            final String logsDir = logsDirs.get(i);
            listenerExecutor.submit(new Runnable() {
                @Override
                public void run() {
                    LOG.info("Starting directory [{}] watcher daemon for JVM [{}].", logsDir, jvmId);
                    try {
                        LOG.debug("Registering watcher on {}", logsDir);
                        FileSystemManager fsManager = VFS.getManager();
                        FileObject listendir = fsManager.resolveFile(logsDir);
                        DefaultFileMonitor fm = new DefaultFileMonitor(new FileListener() {
                            @Override
                            public void fileCreated(FileChangeEvent event) throws Exception {
                                LOG.debug("Directory Watcher: Received notify about '{}' with kind ENTRY_CREATE", event.getFile().getName().getBaseName());
                                process(new File(event.getFile().getName().getPath()));
                            }

                            @Override
                            public void fileDeleted(FileChangeEvent event) throws Exception {
                                // just ignore
                            }

                            @Override
                            public void fileChanged(FileChangeEvent event) throws Exception {
                                LOG.debug("Directory Watcher: Received notify about '{}' with kind ENTRY_MODIFY", event.getFile().getName().getBaseName());
                                process(new File(event.getFile().getName().getPath()));
                            }

                            private synchronized void process(File f) {
                                try {
                                    if (!extensionMatches(f)) {
                                        LOG.debug("Directory Watcher: Extension doesn't match for {}", f.getName());
                                    }
                                    syncFiles(f, logsDir, jvmId);
                                } catch (Throwable t) {
                                    LOG.error(t.getMessage(), t);
                                }
                            }
                        });
                        fm.setRecursive(true);
                        fm.addFile(listendir);
                        fm.start();
                        Thread.sleep(Long.MAX_VALUE);
                    } catch (Throwable t) {
                        LOG.error(t.getMessage(), t);
                    } finally {
                        LOG.info("Stopping directory watcher daemon.");
                    }
                }
            });
        }
        conductorExecutor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                LOG.debug("Conductor process started.");
                for (int i = 0; i < jvmIds.size(); i++) {
                    try {
                        final String jvmId = jvmIds.get(i);
                        File target = new File(dataDir + UPLOAD_DIR + "/" + jvmId);
                        if (!target.exists()) {
                            target.mkdirs();
                        }
                        List<File> files = new ArrayList<File>(FileUtils.listFiles(target, null, false));
                        for (final File f : files) {
                            LOG.debug("Conductor {}: Checking {}", jvmId, f.getName());
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
                                                    if (!isTimestampedOnly(f)) {
                                                        LOG.debug("Uploading {}: {}", jvmId, f.getName());
                                                        rm.upload(f, jvmId);
                                                    } else {
                                                        LOG.error("Conductor ERROR: Log File {} doesn't contain datestamps," +
                                                                " can't process it. Consider using -XX:+PrintGCDateStamps flag.", f.getName());
                                                    }
                                                    zero(f);
                                                } else {
                                                    LOG.debug("Not uploading {}: {}", jvmId, f.getName());
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
            }
        }, filesSyncMs, filesSyncMs, TimeUnit.MILLISECONDS);
        ttlExecutor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                for (String jvmId : jvmIds) {
                    try {
                        LOG.debug("TTL process started.");
                        File target = new File(dataDir + UPLOAD_DIR + "/" + jvmId);
                        if (!target.exists()) {
                            target.mkdirs();
                        }
                        List<File> files = new ArrayList<File>(FileUtils.listFiles(target, null, false));
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
            }
        }, 30, 30, TimeUnit.MINUTES);
    }

    private boolean isTimestampedOnly(File f) throws Exception {
        InputStream is = new GZIPInputStream(new FileInputStream(f));
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            try {
                int count = 0;

                String str;
                while (count <= TIMESTAMP_FIND_LIMIT && (str = br.readLine()) != null) {
                    count++;
                    if (str.matches(TIMESTAMP_PATTERN)) {
                        return true;
                    }
                }
            } finally {
                br.close();
            }
        } finally {
            is.close();
        }
        return false;
    }

    private void checkAndScheduleForUpload(final File f, String jvmId) {
        try {
            Long lastModified = lastModifiedCache.getIfPresent(f.getName());
            long fileLastModified = f.lastModified();
            if (lastModified == null || lastModified == 0 || fileLastModified == 0
                    || lastModified != fileLastModified) {
                String hex;
                FileInputStream fis = new FileInputStream(f);
                try {
                    if (isGzipped(f)) {
                        hex = DigestUtils.sha1Hex(new GZIPInputStream(fis));
                    } else {
                        hex = DigestUtils.sha1Hex(fis);
                    }
                } finally {
                    fis.close();
                }
                String fileName = hex + ".log.gz";
                String dr = dataDir + UPLOAD_DIR + "/" + jvmId;
                if (!new File(dr).exists()) {
                    new File(dr).mkdirs();
                }
                File target = new File(dr, fileName);
                if (!target.exists()) {
                    LOG.debug("File Sync: Copying {} to {}", f.getName(), fileName);
                    GZIPOutputStream gos = new GZIPOutputStream(new FileOutputStream(target));
                    try {
                        if (isGzipped(f)) {
                            GZIPInputStream gzip = new GZIPInputStream(new FileInputStream(f));
                            try {
                                IOUtils.copy(gzip, gos);
                            } finally {
                                gzip.close();
                            }
                        } else {
                            FileUtils.copyFile(f, gos);
                        }
                    } finally {
                        gos.close();
                    }
                } else {
                    LOG.debug("File Sync: {} already exists, {}.", fileName, fileLastModified);
                }
                lastModifiedCache.put(f.getName(), fileLastModified);
            } else {
                LOG.debug("Skipping {}, as its [lastModified={}] didn't changed.", f.getName(), fileLastModified);
            }
        } catch (Throwable t) {
            LOG.error(t.getMessage(), t);
        }
    }

    private void syncFiles(File f, String logsDir, String jvmId) throws IOException {
        for (File file : new ArrayList<File>(FileUtils.listFiles(new File(logsDir), null, false))) {
            if (!file.getName().equals(f.getName()) && extensionMatches(file)) {
                LOG.debug("Checking {} for possible sync.", file.getName());
                checkAndScheduleForUpload(file, jvmId);
            }
        }
    }

    private boolean extensionMatches(File f) {
        return f.getName().contains(extension) &&
                (f.getName().endsWith(extension)
                        || f.getName().endsWith(extension + ".gz")
                        || f.getName().matches(ROLL_LOG_EXTENSION_PATTERN));
    }


    private boolean isGzipped(File f) {
        return f.getName().endsWith(".gz");
    }

    private void loadAnalyze() throws Exception {
        String accountId = call(GET_ACCOUNT_ID, Collections.<String, String>emptyMap()).asText();
        JsonNode analyze = call(GET_ANALYZE, Collections.singletonMap("id", analyzeId));
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
        this.s3ResourceManager = new S3ResourceManager(connector, basePath, accountId, analyzeId);
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
            FileUtils.write(file, "", "UTF-8");
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
