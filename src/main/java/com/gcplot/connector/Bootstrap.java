package com.gcplot.connector;

import com.beust.jcommander.IValueValidator;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:art.dm.ser@gmail.com">Artem Dmitriev</a>
 *         3/28/17
 */
public class Bootstrap {
    private static final Logger LOG = LoggerFactory.getLogger(Bootstrap.class);
    private static final ObjectMapper JSON_FACTORY = new ObjectMapper();
    private static final String GET_ANALYZE = "/analyse/get";

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
    @Parameter(names = { "-extension" }, description = "GC Log Files extention suffix (before .N number for rotating logs)")
    private String extension = ".log";
    @Parameter(names = { "-reaload_config_ms" }, description = "Config reload period in milliseconds.")
    private long reloadConfigMs = 30000;

    private CloseableHttpClient httpclient = HttpClients.createDefault();
    private ScheduledExecutorService configurationReloader = Executors.newSingleThreadScheduledExecutor();
    private ExecutorService syncExecutor = Executors.newSingleThreadExecutor();
    private ExecutorService uploadExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);
    private JsonNode analyze;
    private volatile S3ResourceManager s3ResourceManager;

    public void run() throws Exception {
        loadAnalyze();
        configurationReloader.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                LOG.info("Reloading configuration.");
                try {
                    loadAnalyze();
                } catch (Throwable t) {
                    LOG.error(t.getMessage(), t);
                }
            }
        }, reloadConfigMs, reloadConfigMs, TimeUnit.MILLISECONDS);

    }

    private void loadAnalyze() throws Exception {
        analyze = call(GET_ANALYZE, Collections.singletonMap("id", analyzeId));
        if (analyze.has("id")) {
            String sourceTypeStr = analyze.get("source_type").asText("");
            if (Strings.isNullOrEmpty(sourceTypeStr)) {
                LOG.error("Analyze Group - Source Type is empty.");
            } else {
                SourceType sourceType = SourceType.by(sourceTypeStr);
                if (sourceType == null) {
                    LOG.error("Source Type {} is not supported by this version. Consider updating.");
                } else {
                    Properties props = Utils.fromString(analyze.get("source_config").asText(""));

                    if (sourceType == SourceType.NONE) {
                        LOG.info("Analyze Group {} has none Source Type set. Exiting.");
                    } else if (sourceType == SourceType.GCS) {
                        LOG.error("Source Type {} is not supported by this version. Consider updating.");
                    } else {
                        reloadResourceManager(sourceType,  props);
                    }
                }
            }
        } else {
            LOG.error("Unknown Analyze Group response: {}", analyze);
        }
    }

    private void reloadResourceManager(SourceType sourceType, Properties props) throws Exception {
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
        S3ResourceManager resourceManager = new S3ResourceManager();
        resourceManager.setConnector(connector);
        resourceManager.setBasePath(basePath);
        this.s3ResourceManager = resourceManager;
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
        CloseableHttpResponse resp = httpclient.execute(get);
        return JSON_FACTORY.readTree(resp.getEntity().getContent());
    }

    public static void main(String[] args) {
        try {
            LOG.info("Starting GCPlot connector.");

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
